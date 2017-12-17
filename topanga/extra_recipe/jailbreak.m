//
//  jailbreak.m
//  topanga
//
//  Created by Abraham Masri @cheesecakeufo on 15/12/2017.
//  Copyright © 2017 Abraham Masri @cheesecakeufo. All rights reserved.
//

#include "jailbreak.h"
#include "libjb.h"
#include "kutils.h"
#include "kcall.h"
#include "symbols.h"
#include "kmem.h"
#include "amfi_codesign.h"
#include "patchfinder64_11.h"

#include <errno.h>
#include <dirent.h>

mach_port_t tfp0 = MACH_PORT_NULL;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

size_t
kread(uint64_t where, void *p, size_t size)
{

    if(tfp0 == MACH_PORT_NULL) {
        printf("[ERROR]: tfp0's port is null!\n");
    }

    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);

        if (rv || sz == 0) {
            printf("[ERROR]: error reading buffer at @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

uint64_t
kread_uint64(uint64_t where)
{
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t
kread_uint32(uint64_t where)
{
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t
kwrite(uint64_t where, const void *p, size_t size)
{

    if(tfp0 == MACH_PORT_NULL) {
        printf("[ERROR]: tfp0's port is null!\n");
    }

    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            printf("[ERROR]: error copying buffer into region: @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

size_t
kwrite_uint64(uint64_t where, uint64_t value)
{
    return kwrite(where, &value, sizeof(value));
}

size_t
kwrite_uint32(uint64_t where, uint32_t value)
{
    return kwrite(where, &value, sizeof(value));
}

/*
 * Purpose: iterates over the procs and finds our proc
 */
uint64_t get_proc_for_pid(pid_t target_pid) {
    
    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));

        // get the process pid
        uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        
        if(pid == target_pid) {
            return bsd_info;
        }

        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
        
        if(struct_task == -1)
            return -1;
    }
    return -1; // we failed :/
}

/*
 * Purpose: iterates over the procs and finds a pid with given name
 */
pid_t get_pid_for_name(char *name) {
    
    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        char comm[MAXCOMLEN+1];
        kread(bsd_info + 0x268 /* KSTRUCT_OFFSET_PROC_COMM (is this iPhone X offset??) */, comm, 17);

        if(strcmp(name, comm) == 0) {

            // get the process pid
            uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
            return (pid_t)pid;
        }
        
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
        
        if(struct_task == -1)
            return -1;
    }
    return -1; // we failed :/
}

/*
 * Purpose: iterates over the procs and finds a proc with given name
 */
NSMutableArray *processed_procs;
uint64_t get_proc_for_name(char *name) {
    
    if(processed_procs == nil)
        processed_procs = [[NSMutableArray alloc] init];
    
    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        
        if([processed_procs containsObject:@(bsd_info)])
            continue;

        
        char comm[MAXCOMLEN+1];
        kread(bsd_info + 0x268 /* KSTRUCT_OFFSET_PROC_COMM (is this iPhone X offset??) */, comm, 17);
        
        if(strcmp(name, comm) == 0) {
            
            return bsd_info;
        }
        
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
        
        [processed_procs addObject:@(bsd_info)];
        if(struct_task == -1)
            return -1;
    }
    return -1; // we failed :/
}


uint64_t our_proc = 0;
uint64_t our_cred = 0;

void set_uid0 () {
    
    kern_return_t ret = KERN_SUCCESS;
    
    if(our_proc == 0)
        our_proc = get_proc_for_pid(getpid());
    
    if(our_proc == -1) {
        printf("[ERROR]: no our proc. wut\n");
        ret = KERN_FAILURE;
        return;
    }
    
    extern uint64_t kernel_task;
    
    uint64_t kern_ucred = kread_uint64(kernel_task + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    if(our_cred == 0)
        our_cred = kread_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);
    
    uint64_t offsetof_p_csflags = 0x2a8;
    
    uint32_t csflags = kread_uint32(our_proc + offsetof_p_csflags);
    kwrite_uint32(our_proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD));
    
    setuid(0);
    
}

void set_cred_back () {
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);
}



kern_return_t mount_rootfs() {
    
    kern_return_t ret = KERN_SUCCESS;
    
    NSLog(@"kaslr_slide: %llx\n", kaslr_slide);
    NSLog(@"passing kernel_base: %llx\n", kernel_base);
    
    int rv = init_kernel(kernel_base, NULL);
    
    if(rv != 0) {
        NSLog(@"[ERROR]: could not initialize kernel\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    NSLog(@"[INFO]: sucessfully initialized kernel\n");
    
    uint64_t rootvnode = find_rootvnode();
    NSLog(@"_rootvnode: %llx (%llx)\n", rootvnode, rootvnode - kaslr_slide);
    
    if(rootvnode == 0) {
        ret = KERN_FAILURE;
        return ret;
    }
    
    uint64_t rootfs_vnode = kread_uint64(rootvnode);
    NSLog(@"rootfs_vnode: %llx\n", rootfs_vnode);
    uint64_t v_mount = kread_uint64(rootfs_vnode + 0xd8);
    NSLog(@"v_mount: %llx (%llx)\n", v_mount, v_mount - kaslr_slide);
    uint32_t v_flag = kread_uint32(v_mount + 0x71);
    NSLog(@"v_flag: %x (%llx)\n", v_flag, v_flag - kaslr_slide);
    kwrite_uint32(v_mount + 0x71, v_flag & ~(1 << 6));

    set_uid0();
    printf("our uid: %d\n", getuid());
    char *nmz = strdup("/dev/disk0s1s1");
    rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
    
    if(rv == -1) {
        printf("[ERROR]: could not mount '/': %d\n", rv);
    } else {
        printf("[INFO]: successfully mounted '/'\n");
    }
    

    return ret;
}

kern_return_t unpack_bootstrap() {
    
    kern_return_t ret = KERN_SUCCESS;

    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);
    
    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];

    NSString *bootstrap_path = [execpath stringByAppendingPathComponent:@"bootstrap.tar"];
    NSString *cydia64_path = [execpath stringByAppendingPathComponent:@"cydia64.tar"];
    
    
    if(([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]) == NO) {

        chdir("/");
        FILE *bootstrap = fopen([bootstrap_path UTF8String], "r");
        untar(bootstrap, "/");
        fclose(bootstrap);

        // temp (install latest Cydia)
        chdir("/");
        FILE *cydia64 = fopen([cydia64_path UTF8String], "r");
        untar(cydia64, "/");
        fclose(cydia64);
    
        // Show hidden apps
        NSMutableDictionary* md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
        [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];

        // NO to Cydia stashing
        open("/.cydia_no_stash", O_RDWR | O_CREAT);
        
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
    
        set_cred_back();
        extern void uicache(void);
        uicache(); // used to show Cydia.app
        set_uid0();
        
        char *path = "/var/mobile/Library/Caches";
        
        DIR *mydir;
        struct dirent *myfile;
        
        int fd = open(path, O_RDONLY, 0);
        
        
        mydir = fdopendir(fd);
        while((myfile = readdir(mydir)) != NULL) {
            
            NSString *file_name = [NSString stringWithFormat:@"%s", strdup(myfile->d_name)];
            if ([file_name containsString:@".csstore"]) {
                
                NSLog(@"[INFO]: deleting csstore: %@", file_name);
                
                NSString *full_path = [NSString stringWithFormat:@"%s/%@", path, file_name];
                unlink(strdup([full_path UTF8String]));
                
            }
            
        }
        
        closedir(mydir);
        close(fd);
        
        // kill lsd
        pid_t lsd_pid = get_pid_for_name("lsd");
        kill(lsd_pid, SIGKILL);
        
        pid_t lsdiconsservice_pid = get_pid_for_name("lsdiconservice");
        kill(lsdiconsservice_pid, SIGKILL);
        
        // remove caches
        unlink("/var/mobile/Library/Caches/com.apple.springboard-imagecache-icons");
        unlink("/var/mobile/Library/Caches/com.apple.springboard-imagecache-icons.plist");
        unlink("/var/mobile/Library/Caches/com.apple.springboard-imagecache-smallicons");
        unlink("/var/mobile/Library/Caches/com.apple.springboard-imagecache-smallicons.plist");
        
        unlink("/var/mobile/Library/Caches/SpringBoardIconCache");
        unlink("/var/mobile/Library/Caches/SpringBoardIconCache-small");
        unlink("/var/mobile/Library/Caches/com.apple.IconsCache");
        
        
        // kill installd
        pid_t installd_pid = get_pid_for_name("installd");
        kill(installd_pid, SIGKILL);
        
    }

//    char * original_dir_path = "/Applications/Cydia.app";
//
//    DIR *mydir;
//    struct dirent *myfile;
//
//    int fd = open(original_dir_path, O_RDONLY, 0);
//
//    mydir = fdopendir(fd);
//    while((myfile = readdir(mydir)) != NULL) {
//
//        if(strcmp(myfile->d_name, ".") == 0 || strcmp(myfile->d_name, "..") == 0)
//            continue;
//
//        printf("[FILE]: %s\n", myfile->d_name);
//        chmod(strdup([[NSString stringWithFormat:@"/Applications/Cydia.app/%s", myfile->d_name] UTF8String]), 0777);
//        chown(strdup([[NSString stringWithFormat:@"/Applications/Cydia.app/%s", myfile->d_name] UTF8String]), 0, 0);
//    }

    printf("[INFO]: finished installing bootstrap and friends\n");

    // "fix" containermanagerd
    uint64_t containermanagerd_proc = get_proc_for_pid(get_pid_for_name("containermanager"));
    
    if(containermanagerd_proc == -1) {
        printf("[ERROR]: no containermanagerd. wut\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    printf("[INFO]: got containermanagerd's proc: %llx\n", containermanagerd_proc);
    
    // fix containermanagerd
    uint64_t contaienrmanagerd_cred = kread_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    printf("[INFO]: got containermanagerd's ucred: %llx\n", contaienrmanagerd_cred);

    extern uint64_t kernel_task;
    uint64_t kern_ucred = kread_uint64(kernel_task + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    kwrite_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);
    
    
    uint64_t trust_cache = find_trustcache();
    uint64_t amficache = find_amficache();
    
    printf("trust_cache = 0x%llx\n", trust_cache);
    printf("amficache = 0x%llx\n", amficache);
    
    struct trust_mem mem;
    mem.next = kread_uint64(trust_cache);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;

    // -------
    uint8_t *amfi_hash = amfi_grab_hashes("/Applications/Cydia.app/Cydia");
    memmove(mem.hash[0], amfi_hash, 20);
    mem.count = 1; // just one atm
    // ------
    

    uint64_t kernel_trust = kmem_alloc(sizeof(mem));
//    mach_vm_allocate(tfp0, (mach_vm_address_t *)&kernel_trust, sizeof(mem), VM_FLAGS_ANYWHERE);;
    printf("alloced: 0x%zx => 0x%llx\n", sizeof(mem), kernel_trust);
    

    kwrite(kernel_trust, &mem, sizeof(mem));
//    kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
    wk64(trust_cache, kernel_trust);
    

    

    pid_t pd;
    posix_spawn(&pd, "/Applications/Cydia.app/Cydia", NULL, NULL, (char **)&(const char*[]){ "/Applications/Cydia.app/Cydia", NULL }, NULL);


    int tries = 3;
    while (tries-- > 0) {
        sleep(1);
        uint64_t proc = kread_uint64(0xFFFFFFF007673D68 + kaslr_slide);
        while (proc) {
            uint32_t pid = kread_uint32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));

            if (pid == pd) {
                uint32_t csflags = kread_uint32(proc  + 0x2a8 /* csflags */);
                csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
                kwrite_uint32(proc  + 0x2a8 /* csflags */, csflags);
                printf("empower\n");
                tries = 0;
                break;
            }
            proc = kread_uint64(proc);
        }
    }
    waitpid(pd, NULL, 0);

    
    while (1) {

        uint64_t cydia_proc = get_proc_for_name("Cydia");

        uint32_t csflags = kread_uint32(cydia_proc  + 0x2a8 /* csflags */);
        csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
        kwrite_uint32(cydia_proc  + 0x2a8 /* csflags */, csflags);
        kwrite_uint64(cydia_proc+ 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, contaienrmanagerd_cred);
        printf("empowered Cydia!\n");
    }
    
    return ret;
}

/*
 *  Purpose: since iOS 11 uses SHA256 and libjb doesn't support it yet
 *  I had to re-write this :/
 *  references: codesign.c (Apple)
 */
uint8_t *calculate_sha256(uint8_t* cs_CodeDirectory) {
    
// from xerub's and INF3995
#define SWAP_UINT32(val)   \
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF); \
    (val << 16) | (val >> 16);

    uint32_t* cs_CodeDirectory_count = (uint32_t*)cs_CodeDirectory;
    
    uint32_t realsize = 0;
    int count = 0;
    for (count = 0; count < 10; count++) {
        
        uint32_t magic = SWAP_UINT32(cs_CodeDirectory_count[count]);
        
        switch(magic) {
            case CSMAGIC_REQUIREMENTS:
                break;
            case CSMAGIC_CODEDIRECTORY:

                realsize = SWAP_UINT32(cs_CodeDirectory_count[count + 1]);
                cs_CodeDirectory += 4 * count;
                
                break;
        }
    }
    printf("[INFO]: realsize: %08x\n", realsize);
    
    uint8_t *result = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(cs_CodeDirectory, realsize, result);
    return result;
}



/*
 *  Purpose: grabs hashes for a dir (similar to xerub's but SHA256)
 *  parts were taken from triple_fetch and MachOSign
 */
uint8_t *amfi_grab_hashes(const char *path) {
    
    uint8_t *result = load_code_signatures(path);
    
    printf("[INFO]: code signature for %s: %s\n", path, result);
    
    // calculate the hash
    uint8_t *amfi_hash = calculate_sha256(result);
    printf("[INFO]: amfi_hash for %s: %s\n", path, amfi_hash);
    
    return amfi_hash;
}



/*
 
trust cache (iOS 10.x/iPad Air):
 
(0): search for string 'amfi_prevent_old_entitled_platform'
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CD8 loc_FFFFFFF0064F8CD8                    ; CODE XREF: sub_FFFFFFF0064F8ADC+1D8↑j
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CD8                 ADRP            X0, #aAmfiPreventOld@PAGE ; "amfi_prevent_old_entitled_platform_bina"...
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CDC (1)             ADD             X0, X0, #aAmfiPreventOld@PAGEOFF ; "amfi_prevent_old_entitled_platform_bina"...
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CE0                 MOV             W2, #4
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CE4                 ADD             X1, SP, #0x50+var_34
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CE8                 BL              sub_FFFFFFF0064FAA60
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CEC (2)             CBZ             W0, loc_FFFFFFF0064F8D00 (3)
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CF0                 LDR             W8, [SP,#0x50+var_34]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CF4                 CBZ             W8, loc_FFFFFFF0064F8D00
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CF8                 MOV             W8, #1
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8CFC                 STRB            W8

com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D00 loc_FFFFFFF0064F8D00 (3)                    ; CODE XREF: sub_FFFFFFF0064F8ADC+A0↑j
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D00                                 ; sub_FFFFFFF0064F8ADC+210↑j ...
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D00                 BL              sub_FFFFFFF0064F6508 (4)
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F8D04                 BL              sub_FFFFFFF0064FAA00

com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 sub_FFFFFFF0064F6508 (4)                  ; CODE XREF: sub_FFFFFFF0064F8ADC:loc_FFFFFFF0064F8D00↓p
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 var_s0          =  0
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508                 STP             X29, X30, [SP,#-0x10+var_s0]!
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F650C                 MOV             X29, SP
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6510                 ADRP            X8, #qword_FFFFFFF00761B328@PAGE (5) the address of the QWORD is trust cache
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6514                 STR             XZR, [X8,#qword_FFFFFFF00761B328@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6518                 BL              sub_FFFFFFF0064FAA00
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F651C                 ADRP            X8, #qword_FFFFFFF00761B320@PAGE
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6520                 STR             X0, [X8,#qword_FFFFFFF00761B320@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6524                 LDP             X29, X30, [SP+var_s0],#0x10
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528                 RET
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528 ; End of function sub_FFFFFFF0064F6508
 
 
 
trust cache (iOS 11.x / iPhone X):
 
(0): com.apple.driver.AppleMobileFileIntegrity:__bss there will be a list of qwords
(1): check the ref(s) to each one (choose the first ref ADRP)
(2): if the func is like this then and your QWORD is the first one in the func then it's the correct one!

com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 sub_FFFFFFF0064F6508                    ; CODE XREF: sub_FFFFFFF0064F8ADC:loc_FFFFFFF0064F8D00↓p
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508 var_s0          =  0
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6508                 STP             X29, X30, [SP,#-0x10+var_s0]!
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F650C                 MOV             X29, SP
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6510                 ADRP            X8, #qword_FFFFFFF00761B328@PAGE <-----
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6514                 STR             XZR, [X8,#qword_FFFFFFF00761B328@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6518                 BL              sub_FFFFFFF0064FAA00
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F651C                 ADRP            X8, #qword_FFFFFFF00761B320@PAGE
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6520                 STR             X0, [X8,#qword_FFFFFFF00761B320@PAGEOFF]
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6524                 LDP             X29, X30, [SP+var_s0],#0x10
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528                 RET
com.apple.driver.AppleMobileFileIntegrity:__text:FFFFFFF0064F6528 ; End of function sub_FFFFFFF0064F6508
 
 */


kern_return_t go_kppless() {
//    int rv;
//
//    kern_return_t ret = KERN_SUCCESS;
//
//    char path[4096];
//    uint32_t size = sizeof(path);
//    _NSGetExecutablePath(path, &size);
//    char *pt = realpath(path, NULL);
//
//    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];
//
//
//    NSString *bootstrap = [execpath stringByAppendingPathComponent:@"bootstrap.dmg"];
//    const char *jl;
//
//
//
//    uint64_t containermanagerd_proc = 0x0;
//
//    if(containermanagerd_proc == -1) {
//        printf("[ERROR]: no containermanagerd. wut\n");
//        ret = KERN_FAILURE;
//        return ret;
//    }
//
//
//    printf("[INFO]: got containermanagerd's proc: %llx\n", containermanagerd_proc);
//
//    // fix containermanagerd
//    uint64_t contaienrmanagerd_cred = kread_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
//    printf("[INFO]: got containermanagerd's ucred: %llx\n", contaienrmanagerd_cred);
//
//
//
//    uint64_t our_proc = get_proc_for_pid(getpid());
//
//    if(our_proc == -1) {
//        printf("[ERROR]: no our proc. wut\n");
//        ret = KERN_FAILURE;
//        return ret;
//    }
//
//    printf("kaslr_slide: %llx\n", kaslr_slide);
//    printf("passing kernel_base: %llx\n", kernel_base);
//
//    rv = init_kernel(kernel_base, NULL);
//
//    if(rv != 0) {
//        printf("[ERROR]: could not initialize kernel\n");
//        ret = KERN_FAILURE;
//        return ret;
//    }
//
//    uint64_t trust_chain = find_trustcache();
//    uint64_t amficache = find_amficache();
//
//    if(trust_chain == 0) {
//        trust_chain = 0xFFFFFFF0076DF428 + kaslr_slide;
//    }
//
//    printf("[INFO]: trust_chain: %llx\n", trust_chain);
//    printf("[INFO]: amficache: %llx\n", amficache);
//
//    term_kernel();
//    set_uid0();
//
//    /* 2. extract and run hdik */
//    jl = "/tmp/hdik";
//    long dmg = HFSOpen("/usr/standalone/update/ramdisk/arm64SURamDisk.dmg", 27);
//    if (dmg >= 0) {
//        long len = HFSReadFile(dmg, "/usr/sbin/hdik", gLoadAddr, 0, 0);
//        printf("hdik = %ld\n", len);
//        if (len > 0) {
//            int fd = creat(jl, 0755);
//            if (fd >= 0) {
//                write(fd, gLoadAddr, len);
//                close(fd);
//            }
//        }
//        HFSClose(dmg);
//    }
//
//    uint32_t csflags = kread_uint32(our_proc + 0x2a8 /* csflags */);
//    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
//    kwrite_uint32(our_proc  + 0x2a8 /* csflags */, csflags);
//    printf("empowered US\n");
//
//    printf("jl BOOTSTRAP: %s %s\n", jl, [bootstrap UTF8String]);
//    pid_t pd;
//    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, [bootstrap UTF8String], "-nomount", NULL }, NULL);
//    printf("[INFO]: PID: %d\n", pd);
//
//    {
//        int tries = 3;
//        while (tries-- > 0) {
//            sleep(1);
//            uint64_t proc = kread_uint64(0xFFFFFFF007673D68 + kaslr_slide);
//            while (proc) {
//                uint32_t pid = kread_uint32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
//                if (pid == pd) {
//                    uint32_t csflags = kread_uint32(proc + 0x2a8 /* csflags */);
//                    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
//                    kwrite_uint32(proc  + 0x2a8 /* csflags */, csflags);
//                    printf("empower\n");
//                    tries = 0;
//                    break;
//                }
//                proc = kread_uint64(proc);
//            }
//        }
//    }
//
//    waitpid(pd, NULL, 0);
////    {kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);return 0;}
//    sleep(5);
//
//    char thedisk[11];
//    strcpy(thedisk, "/dev/diskN");
//    for (int i = 9; i > 2; i--) {
//        struct stat st;
//        thedisk[9] = i + '0';
//        rv = stat(thedisk, &st);
//        if (rv == 0) {
//            break;
//        }
//    }
//
//    printf("thedisk: %s\n", thedisk);
//
////    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);
//
////    char * original_dir_path = "/usr/standalone/update/ramdisk/";
////
////    DIR *mydir;
////    struct dirent *myfile;
////
////    int fd = open(original_dir_path, O_RDONLY, 0);
////
////    mydir = fdopendir(fd);
////    while((myfile = readdir(mydir)) != NULL) {
////
////        if(strcmp(myfile->d_name, ".") == 0 || strcmp(myfile->d_name, "..") == 0)
////            continue;
////
////        printf("[CPBBB]: %s\n", myfile->d_name);
////    }
//
//    /* 3. mount */
//    memset(&args, 0, sizeof(args));
//    args.fspec = thedisk;
//    args.hfs_mask = 0777;
//    //args.hfs_encoding = -1;
//    //args.flags = HFSFSMNT_EXTENDED_ARGS;
//    //struct timeval tv = { 0, 0 };
//    //gettimeofday((struct timeval *)&tv, &args.hfs_timezone);
//
//    rv = mount("hfs", "/Developer", MNT_RDONLY, &args);
//    printf("mount: %d - uid: %d\n", rv, getuid());
//    printf("errno: %d\n", errno);
//    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);
//
//    /* 4. inject trust cache */
//
//    printf("trust_chain = 0x%llx\n", trust_chain);
//
//    struct trust_mem mem;
//    mem.next = kread_uint64(trust_chain);
//    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
//    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;

//#ifdef WANT_CYDIA
//    rv = grab_hashes("/", kread, amficache, mem.next);
//#else
//    rv = grab_hashes("/Developer", kread, amficache, mem.next);
//#endif
//    printf("rv = %d, numhash = %d\n", rv, numhash);
//
//    size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
//    uint64_t kernel_trust = 0;
//    mach_vm_allocate(tfp0, (mach_vm_address_t *)&kernel_trust, length, VM_FLAGS_ANYWHERE);
//    printf("[INFO]: alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
//
//    mem.count = numhash;
//    kwrite(kernel_trust, &mem, sizeof(mem));
//    kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
//    kwrite_uint64(trust_chain, kernel_trust);
//
//    free(allhash);
//    free(allkern);
//    free(amfitab);
//
//    /* 5. load daemons */
//
//#ifdef WANT_CYDIA
//    // FIXME
//    rv = posix_spawn(&pd, pt, NULL, NULL, (char **)&(const char*[]){ pt, "derp", "/Library/LaunchDaemons", NULL }, NULL);
//#else
//    rv = posix_spawn(&pd, pt, NULL, NULL, (char **)&(const char*[]){ pt, "derp", "/Developer/Library/LaunchDaemons/com.openssh.sshd.plist", NULL }, NULL);
//#endif
//
//    int tries = 3;
//    while (tries-- > 0) {
//        sleep(1);
//        uint64_t proc = kread_uint64(allproc);
//        while (proc) {
//            uint32_t pid = kread_uint32(proc + offsetof_p_pid);
//            if (pid == pd) {
//                uint32_t csflags = kread_uint32(proc + offsetof_p_csflags);
//                csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
//                kwrite_uint32(proc + offsetof_p_csflags, csflags);
//                printf("empower\n");
//                tries = 0;
//                break;
//            }
//            proc = kread_uint64(proc);
//        }
//    }
//
//    waitpid(pd, NULL, 0);
//
//    if (proc) {
//        kwrite_uint64(proc + offsetof_p_ucred, c_cred);
//    }
//
//    printf("done\n");
//
//    FILE *f = fopen("/tmp/k", "wt");
//    fprintf(f, "0x%llx 0x%llx\n0x%llx 0x%llx\n", kernel_base, kaslr_shift, trust_chain, amficache);
//    fclose(f);
    return 0;
}
