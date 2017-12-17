//
//  amfi_codesign.m
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//

#include <mach-o/fat.h>
#include "amfi_codesign.h"
#include <mach-o/loader.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>


static CFMutableDictionaryRef lc_code_sig(uint8_t *lc_code_signature, size_t lc_code_signature_len)
{
    CFMutableDictionaryRef code_signature =
    CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
//    require(code_signature, out);
    
    CS_SuperBlob *sb = (CS_SuperBlob*)lc_code_signature;
//    require(ntohl(sb->magic) == CSMAGIC_EMBEDDED_SIGNATURE, out);
    uint32_t count;
    for (count = 0; count < ntohl(sb->count); count++) {
        //uint32_t type = ntohl(sb->index[count].type);
        uint32_t offset = ntohl(sb->index[count].offset);
        uint8_t *bytes = lc_code_signature + offset;
        //fprintf(stderr, "blob[%d]: (type: 0x%.08x, offset: %p)\n", count, type, (void*)offset);
        uint32_t magic = ntohl(*(uint32_t*)bytes);
        uint32_t length = ntohl(*(uint32_t*)(bytes+4));
        //fprintf(stderr, "    magic: 0x%.08x length: %d\n", magic, length);
        switch(magic) {
            case 0xfade7171:
            {
                unsigned char digest[CC_SHA1_DIGEST_LENGTH];
                //                CCDigest(kCCDigestSHA1, bytes, length, digest);
                CC_SHA1(bytes + 8, length - 8, digest);
                
                CFDataRef message = CFDataCreate(kCFAllocatorDefault, digest, sizeof(digest));
//                require(message, out);
                CFDictionarySetValue(code_signature, CFSTR("EntitlementsHash"), message);
                CFRelease(message);
                message = CFDataCreate(kCFAllocatorDefault, bytes+8, length-8);
//                require(message, out);
                CFDictionarySetValue(code_signature, CFSTR("Entitlements"), message);
                CFRelease(message);
                break;
                break;
            }
            default:
                //                fprintf(stderr, "Skipping block with magic: 0x%x\n", magic);
                break;
        }
    }
    return code_signature;
}


uint8_t *load_code_signature(FILE *binary, size_t slice_offset)
{
    bool signature_found = false;
    uint8_t *result = 0;
    struct load_command lc;
    do {
        fread(&lc, sizeof(lc), 1, binary);
        if (lc.cmd == LC_CODE_SIGNATURE) {
            
            printf("[INFO]: found code signature!\n");
            
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, binary);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, binary);
            printf("%d - %d\n", off_cs, size_cs);
            
            signature_found = true;
            uint8_t *cd = malloc(size_cs);
            fseek(binary, off_cs, SEEK_SET);
            fread(cd, size_cs, 1, binary);
            result = cd;
            break;
            
//            struct { uint32_t offset; uint32_t size; } sig;
//            if(fread(&sig, sizeof(sig), 1, binary) != 1) goto out;
//            if(fseek(binary, slice_offset+sig.offset, SEEK_SET) == -1) goto out;
//            size_t length = sig.size;
//            uint8_t *data = malloc(length);
//            if(!(length && data)) goto out;
//            if(fread(data, length, 1, binary) != 1) goto out;


//            result = lc_code_sig(data, length);
//            free(data);
//            break;
        }

        fseek(binary, lc.cmdsize-sizeof(lc), SEEK_CUR);
    } while(lc.cmd || lc.cmdsize); /* count lc */
out:
    if (!signature_found) {
        printf("[ERROR]: No LC_CODE_SIGNATURE segment found\n");
        result = 0;
    }
    return result;
}

uint8_t *load_code_signatures(const char *path) {
    
    uint8_t *result = 0;
    FILE *binary = fopen(path, "r");

    
    struct mach_header header;
    fread(&header, sizeof(header), 1, binary);
    if ((header.magic == MH_MAGIC) || (header.magic == MH_MAGIC_64)) {
        
        // iOS 11 doesn't even support 32-bit
        if (header.magic != MH_MAGIC_64) {
            printf("[WARNING]: skipping a non-64bit header in: %s\n", path);
            goto cleanup;
        }
        
        fseek(binary, sizeof(struct mach_header_64) - sizeof(struct mach_header), SEEK_CUR);
        printf("[INFO]: loading code signature for non-FAT binary: %s\n", path);
        result = load_code_signature(binary, 0 /*non fat*/);
        if(result == 0) {
            printf("[ERROR]: no code signature found!\n");
            goto cleanup;
        }

    } else {
        struct fat_header fat;
        fseek(binary, 0L, SEEK_SET);
        fread(&fat, sizeof(fat), 1, binary);
        
        if(ntohl(fat.magic) != FAT_MAGIC){
            printf("[ERROR]: no FAT_MAGIC found..\n");
            goto cleanup;
        }
        
        uint32_t slice, slices = ntohl(fat.nfat_arch);
        struct fat_arch *archs = calloc(slices, sizeof(struct fat_arch));
        fread(archs, sizeof(struct fat_arch), slices, binary);
        
        for (slice = 0; slice < slices; slice++) {
            
            uint32_t slice_offset = ntohl(archs[slice].offset);
            fseek(binary, slice_offset, SEEK_SET);
            fread(&header, sizeof(header), 1, binary);
            
            // iOS 11 doesn't even support 32-bit
            if (header.magic != MH_MAGIC_64) {
                printf("[WARNING]: skipping a non-64bit header in: %s\n", path);
                continue;
            }
                
            fseek(binary, sizeof(struct mach_header_64) - sizeof(struct mach_header), SEEK_CUR);
            
            printf("[INFO]: loading code signature for FAT binary: %s\n", path);
            result = load_code_signature(binary, slice_offset);
            if(result == 0)
                printf("[ERROR]: no code signature found!\n");

        }
    }
    
cleanup:
    fclose(binary);
    return result;
}
