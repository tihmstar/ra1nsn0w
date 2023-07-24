//
//  main.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <getopt.h>
#include <libgeneral/macros.h>
#include <libipatcher/libipatcher.hpp>
#include <img4tool/img4tool.hpp>
#include <string.h>
#include <algorithm>
#include <cctype>
#include <string>
#include "../include/ra1nsn0w/ra1nsn0w.hpp"
#include "../include/ra1nsn0w/iOSDevice.hpp"
#include <fcntl.h>
#include <sys/stat.h>

extern "C"{
#include <libfragmentzip/libfragmentzip.h>
#include <plist/plist.h>
};

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

#ifndef HAVE_STRTOUL_L
#define strtoul_l _strtoul_l
#endif

#ifndef LC_GLOBAL_LOCALE
# define LC_GLOBAL_LOCALE ((_locale_t)-1) //this is for windows :/
#endif

#define PARSE_PATCH_CONFIG ((!optarg) ? kPatchcfgYes : ((!strcmp(optarg, "optional")) ? kPatchcfgMayFail : (Patchcfg)atoi(optarg)))

static struct option longopts[] = {
    /* Device selectors: */
    { "help",                           no_argument,            NULL, 'h' },
    { "apticket",                       required_argument,      NULL, 't' },
    { "buildid",                        required_argument,      NULL, 'B' },
    { "ecid",                           required_argument,      NULL, 'e' },
    { "wait",                           no_argument,            NULL, 'w' },
    { "32bit",                          no_argument,            NULL,  0  },
    { "dry-run",                        required_argument,      NULL,  0  },
    { "dry-out",                        required_argument,      NULL,  0  },
    { "ota",                            no_argument,            NULL,  0  },

    /* Behavior config: */
    { "variant",                        required_argument,      NULL, 'V' },
    { "nobootx",                        no_argument,            NULL,  0  },
    { "just-dfu",                       no_argument,            NULL,  0  },
    { "just-iboot",                     no_argument,            NULL,  0  },
    { "decrypt-devicetree",             no_argument,            NULL,  0  },
    { "iboot-as-ibec",                  no_argument,            NULL,  0  },
    { "no-sep",                         no_argument,            NULL,  0  },
    { "no-decrypt",                     no_argument,            NULL,  0  },
    { "send-all-components",            no_argument,            NULL,  0  },
    { "srd",                            no_argument,            NULL,  0  },

    /* Customized boot: */
    { "fpatch",                         required_argument,      NULL,  0  },
    { "kernel",                         required_argument,      NULL, 'k' },
    { "ramdisk",                        required_argument,      NULL, 'r' },
    { "sep",                            required_argument,      NULL, 's' },
    { "trustcache",                     required_argument,      NULL, 'c' },
    { "logo",                           required_argument,      NULL, 'l' },
    { "custom-component",               required_argument,      NULL,  0  },
    { "ibec",                           required_argument,      NULL,  0  },
    { "ibss",                           required_argument,      NULL,  0  },
    { "patch",                          required_argument,      NULL,  0  },
    { "sreplace",                       required_argument,      NULL,  0  },

    /* iBEC patches: */
    { "boot-args",                      required_argument,      NULL, 'b' },
    { "iboot-nopatch",                  no_argument,            NULL,  0  },
    { "iboot-no-sigpatch",              no_argument,            NULL,  0  },
    { "iboot-send-signed-sep",          optional_argument,      NULL,  0  },
    { "ipatch-add-rw-and-rx-mappings",  optional_argument,      NULL,  0  },
    { "ipatch-atv4k-enable-uart",       optional_argument,      NULL,  0  },
    { "ipatch-always-production",       optional_argument,      NULL,  0  },
    { "ipatch-always-sepfw-booted",     optional_argument,      NULL,  0  },
    { "ipatch-cmdcall",                 required_argument,      NULL,  0  },
    { "ipatch-cmdhandler",              required_argument,      NULL,  0  },
    { "ipatch-disable-wxn-el3",         optional_argument,      NULL,  0  },
    { "ipatch-dtre-debug-enable",       optional_argument,      NULL,  0  },
    { "ipatch-no-force-dfu",            optional_argument,      NULL,  0  },
    { "ipatch-largepicture",            optional_argument,      NULL,  0  },
    { "ipatch-memcpy",                  optional_argument,      NULL,  0  },
    { "ipatch-nvram-unlock",            optional_argument,      NULL,  0  },
    { "ipatch-sep-force-local",         optional_argument,      NULL,  0  },
    { "ipatch-sep-force-raw",           optional_argument,      NULL,  0  },
    { "ipatch-sep-skip-bpr",            optional_argument,      NULL,  0  },
    { "ipatch-sep-skip-lock",           optional_argument,      NULL,  0  },
    { "ipatch-wtf-pwndfu",              optional_argument,      NULL,  0  },
    { "ra1nra1n",                       required_argument,      NULL,  0  },
    
    /* Kernel patches: */
    { "kernel-nopatch",                 no_argument,            NULL,  0  },
    { "kpatch-codesignature",           optional_argument,      NULL,  0  },
    { "kpatch-mount",                   optional_argument,      NULL,  0  },
    { "kpatch-sandbox",                 optional_argument,      NULL,  0  },
    { "kpatch-nuke-sandbox",            optional_argument,      NULL,  0  },
    { "kpatch-i_can_has_debugger",      no_argument,            NULL,  0  },
    { "kpatch-force-nand-writeable",    optional_argument,      NULL,  0  },
    { "kpatch-always-get-task-allow",   optional_argument,      NULL,  0  },
    { "kpatch-allow-uid",               optional_argument,      NULL,  0  },
    { "kpatch-add-read-bpr",            optional_argument,      NULL,  0  },
    { "kpatch-no-ramdisk-detect",       optional_argument,      NULL,  0  },
    { "kpatch-noemf",                   optional_argument,      NULL,  0  },
    { "kpatch-get-kernelbase-syscall",  optional_argument,      NULL,  0  },
    { "kpatch-tfp0",                    optional_argument,      NULL,  0  },
    { "kpatch-tfp-unrestrict",          optional_argument,      NULL,  0  },
    { "kpatch-setuid",                  optional_argument,      NULL,  0  },
    { "kpatch-force-boot-ramdisk",      optional_argument,      NULL,  0  },
    { "kpatch-hardcode-bootargs",       required_argument,      NULL,  0  },
    { "kpatch-hardcode-boot-manifest-hash",required_argument,   NULL,  0  },
    { "kpatch-root-from-sealed-apfs",   optional_argument,      NULL,  0  },
    { "kpatch-apfs-skip-authenticated-root-hash",optional_argument,NULL,  0  },
    { "sn0wsn0w",                       no_argument,            NULL,  0  },
    
    { NULL, 0, NULL, 0 }
};

std::vector<uint8_t> readFile(const char *filePath){
    std::vector<uint8_t> ret;
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    int err = 0;
    struct stat st = {};

    retassure((fd = open(filePath, O_RDONLY)), "Failed to open file '%s'",filePath);

    retassure(!(err = fstat(fd, &st)), "stat failed on file '%s' with error=%d errno=%d (%s)",filePath,err,errno,strerror(errno));
    ret.resize(st.st_size);
    
    assure(read(fd, ret.data(), ret.size()) == ret.size());
    return ret;
}

plist_t readPlistFromFile(const char *filePath){
    FILE *f = fopen(filePath,"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);

    size_t fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc(fSize);
    fread(buf, fSize, 1, f);
    fclose(f);

    plist_t plist = NULL;

    if (memcmp(buf, "bplist00", 8) == 0)
        plist_from_bin(buf, (uint32_t)fSize, &plist);
    else
        plist_from_xml(buf, (uint32_t)fSize, &plist);

    return plist;
}

char *im4mFormShshFile(const char *shshfile, size_t *outSize, char **generator){
    plist_t shshplist = readPlistFromFile(shshfile);

    plist_t ticket = plist_dict_get_item(shshplist, "ApImg4Ticket");

    char *im4m = 0;
    uint64_t im4msize=0;
    plist_get_data_val(ticket, &im4m, &im4msize);
    if (outSize) {
        *outSize = im4msize;
    }

    if (generator){
        if ((ticket = plist_dict_get_item(shshplist, "generator")))
            plist_get_string_val(ticket, generator);
    }

    plist_free(shshplist);

    return im4msize ? im4m : NULL;
}

void parserUserPatch(std::string userpatch, launchConfig &cfg, bool isFile = false){
    printf("Parsing custom user patch \"%s\"\n",userpatch.c_str());
    ssize_t colunpos = 0;
    uint32_t component = 0;

    retassure((colunpos = userpatch.find(":")) != std::string::npos, "Failed to find ':' What component is this patch for?");

    std::string componentstr = userpatch.substr(0,colunpos);
    std::string patchstr = userpatch.substr(colunpos+1);

    retassure(componentstr.size() == 4, "component needs to be 4 bytes in size");
    component = *(uint32_t*)componentstr.c_str();
    
    while (true) {
        std::vector<uint8_t> patchBytes;
        
        ssize_t nextPatchPos = patchstr.find(";");
        ssize_t commaPos = 0;
        assure((commaPos = patchstr.find(",")) != std::string::npos); //if we have a patch, we need at least <addr> and <patch>

        std::string pAddr = patchstr.substr(0,commaPos);
        std::string pPatch = patchstr.substr(commaPos+1,nextPatchPos);
        
        uint64_t addr = 0;
        assure(sscanf(pAddr.c_str(), "0x%llx",&addr) == 1);
        
        if (isFile) {
            patchBytes = readFile(pPatch.c_str());
        }else{
            patchBytes.resize(pPatch.size());
            for (size_t i = 0; i<pPatch.size(); i+=2) {
                uint32_t byte = 0;
                assure(sscanf(&pPatch.c_str()[i], "%02x",&byte) == 1);
                patchBytes[i/2] = (uint8_t)byte;
            }
            patchBytes.resize(pPatch.size()/2);
        }

        patchfinder::patch p{addr,patchBytes.data(),patchBytes.size()};

        printf("%s: Parsed patch=%p : ",componentstr.c_str(),(void*)p._location);
        for (int i=0; i<p._patchSize; i++) {
            printf("%02x",((uint8_t*)p._patch)[i]);
        }
        printf("\n");
        
        cfg.userPatches[component].push_back(p);
        
        if (nextPatchPos == std::string::npos) break;
        patchstr = patchstr.substr(nextPatchPos+1);
    }
}

void parserCustomComponent(std::string customcomponent, launchConfig &cfg){
    printf("Parsing custom firmware paths \"%s\"\n",customcomponent.c_str());
    ssize_t commapos = 0;
    retassure((commapos = customcomponent.find(",")) != std::string::npos, "Failed to find ',' What component is this path for?");
    
    std::string componentName = customcomponent.substr(0,commapos);
    auto data = readFile(customcomponent.substr(commapos+1).c_str());
    cfg.customComponents[componentName] = data;
}

void parserStringReplacePatch(std::string userpatch, launchConfig &cfg){
    printf("Parsing custom string replace patch \"%s\"\n",userpatch.c_str());
    ssize_t colunpos = 0;
    uint32_t component = 0;

    retassure((colunpos = userpatch.find(":")) != std::string::npos, "Failed to find ':' What component is this patch for?");

    std::string componentstr = userpatch.substr(0,colunpos);
    std::string patchstr = userpatch.substr(colunpos+1);

    retassure(componentstr.size() == 4, "component needs to be 4 bytes in size");
    component = *(uint32_t*)componentstr.c_str();
    
    while (true) {
        uint8_t *patchBytes = NULL;
        cleanup([&]{
            safeFree(patchBytes);
        });
        
        ssize_t nextPatchPos = patchstr.find(";");
        ssize_t commaPos = 0;
        assure((commaPos = patchstr.find(",")) != std::string::npos); //if we have a patch, we need at least <addr> and <patch>

        std::string pFind = patchstr.substr(0,commaPos);
        std::string pReplace = patchstr.substr(commaPos+1,nextPatchPos);

        printf("%s: Parsed repalce patch='%s'->'%s'\n",componentstr.c_str(),pFind.c_str(),pReplace.c_str());
        
        cfg.replacePatches[component].push_back({pFind,pReplace});
        
        if (nextPatchPos == std::string::npos) break;
        patchstr = patchstr.substr(nextPatchPos+1);
    }
}

void cmd_help(){
    printf("Usage: ra1nsn0w [OPTIONS] [IPSW]\n");
    printf("Multipurpose tool for launching custom bootchain\n\n");
    
    printf("Device selectors:\n");
    printf("  -h, --help\t\t\t\t\tDisplays this helpscreen\n");
    printf("  -t, --apticket PATH\t\t\t\tApticket use for bypassing sigchecks (Note: current sigcheck patches require an APTicket)\n");
    printf("  -B  --buildid BUILDID\t\t\t\tspecific buildid instead of iOS ipsw path\n");
    printf("  -e, --ecid ECID\t\t\t\tTarget specific device by its device ECID\n");
    printf("  -w, --wait\t\t\t\t\tWait for device\n");
    printf("      --32bit\t\t\t\t\tUse 32bit patchfinder instead of 64bit\n");
    printf("      --dry-run <device>:<hardware>:<img4>\t\tTest all patches, but don't actually send anything to device. Emulate device (eg. iPhone6,2:n53ap:1)\n");
    printf("      --dry-out <path>\t\t\t\tInstead of sending components to device, write them to the specified directory\n");
    printf("      --ota\t\t\t\t\tFirmwarefile is ota.zip rather than firmware.ipsw\n");

    
    printf("\nBehavior config:\n");
    printf("  -V, --variant <VARIANT>\t\t\tSpecify restore variant to use\n");
    printf("      --decrypt-devicetree\t\t\tSend devicetree decrypted (Usually we wouldn't touch that)\n");
    printf("      --iboot-as-ibect\t\t\t\tBoot iBoot instead of iBEC\n");
    printf("      --just-dfu\t\t\t\tStop in DFU mode\n");
    printf("      --just-iboot\t\t\t\tOnly boot to iBoot, do not send anything to it\n");
    printf("      --nobootx\t\t\t\t\tDon't run \"bootx\" command\n");
    printf("      --no-decrypt\t\t\t\tDo not decrypt files\n");
    printf("      --no-sep\t\t\t\t\tDo not boot rsep\n");
    printf("      --srd\t\t\t\t\tRequest ticket on-the-fly (for SRD)\n");

    printf("\nCustomized boot:\n");
    printf("  -k, --kernel <path>\t\t\t\tManually specify a kernel.im4p to boot\n");
    printf("  -r, --ramdisk <path>\t\t\t\tManually specify a ramdisk.im4p to boot\n");
    printf("  -s, --sep <path>\t\t\t\tManually specify a sep.im4p to boot\n");
    printf("  -c, --trustcache <path>\t\t\tManually specify a .trustcache to boot\n");
    printf("  -l, --logo <path>\t\t\t\tSpecify bootlogo\n");
    printf("      --custom-component=<component>,<path>\tManually specify a firmware component\n");
    printf("      --fpatch=<component>:<addr1>,<file>\tManually specify a patch to a component from file\n");
    printf("      --ibec <path>\t\t\t\tManually specify a iBEC to boot\n");
    printf("      --ibss <path>\t\t\t\tManually specify a iBSS to boot\n");
    printf("      --patch=<component>:<addr1>,<patch1>\tManually specify a patch to a component\n");
    printf("      --send-all-components\t\tSend all components that iboot expects\n");
    printf("      --sreplace=<component>:<findstr,replacestr>;... Patch replace string with other string\n");

    printf("\niBEC patches:\n");
    printf("  -b, --boot-args ARGS\t\t\t\tSpecify kernel bootargs\n");
    printf("      --iboot-nopatch\t\t\t\tDon't modify iBoot (iBSS/iBEC) IM4P and send as it is (only rename to rkrn)\n");
    printf("      --iboot-no-sigpatch\t\t\tDon't apply iBSS/iBEC sigpatches (WARNING: device will not boot past this bootloader!)\n");
    printf("      --iboot-send-signed-sep\tGet a valid ticket and send RestoreSEP\n");
    printf("      --ipatch-add-rw-and-rx-mappings\t\tSets iBoot block writeable at 0x2000000 and loadaddr block executable at 0x4000000\n");
    printf("      --ipatch-always-production\t\tPretend we're in production mode even though we may be demoted\n");
    printf("      --ipatch-always-sepfw-booted\t\tAlways set 'sepfw-booted' in devicetree\n");
    printf("      --ipatch-atv4k-enable-uart\t\tPinmux and enable UART on ATV4k\n");
    printf("      --ipatch-cmdcall NAME\t\t\tPatch command NAME to be an arbitrary call gadget\n");
    printf("      --ipatch-cmdhandler NAME=VALUE\t\tPatch command NAME to jump to VALUE\n");
    printf("            (Example --cmdhandler go=0x41414141 makes go command jump to address 0x41414141)\n");
    printf("      --ipatch-disable-wxn-el3\t\t\tDisable WXN enforcement in EL3 iBoot\n");
    printf("      --ipatch-dtre-debug-enable\t\t\tSet debug-enable in devicetree\n");
    printf("      --ipatch-no-force-dfu\t\t\tSkip iBoot force_dfu checks\n");
    printf("      --ipatch-largepicture\t\t\tRemove setpicture's sizelimit of 0x100000 bytes\n");
    printf("      --ipatch-memcpy\t\t\t\tReplace reboot with memcpy\n");
    printf("      --ipatch-nvram-unlock\t\t\tAllows reading and writing all nvram vars\n");
    printf("      --ipatch-sep-force-local\t\t\tForce booting sepi instead of rsep\n");
    printf("      --ipatch-sep-force-raw\t\t\tForce loading raw rsep\n");
    printf("      --ipatch-sep-skip-bpr\t\t\tDon't set SEP BPR by iBoot\n");
    printf("      --ipatch-sep-skip-lock\t\t\tDon't lock tz0 registers by iBoot\n");
    printf("      --ipatch-wtf-pwndfu\t\t\tPatch WTF image to act as PWNDFU\n");
    printf("      --ra1nra1n <path>\t\t\t\tExecute payload before jumping to kernel\n");

    printf("\nKernel patches:\n");
    printf("     --kernel-nopatch\t\t\t\tDon't modify kernel IM4P and send as it is (only rename to rkrn)\n");
    printf("     --kpatch-add-read-bpr\t\t\tAllow reading BPR status by overwriting syscall 213\n");
    printf("     --kpatch-allow-uid\t\t\t\tAllow using UID key for enc/dec from userspace\n");
    printf("     --kpatch-always-get-task-allow\t\tMake all processes have get-task-allow entitlement\n");
    printf("     --kpatch-apfs-skip-authenticated-root-hash Skip checking for authenticated root hash\n");
    printf("     --kpatch-codesignature\t\t\tAllow unsigned code to run\n");
    printf("     --kpatch-force-boot-ramdisk\t\tAlways imply 'rd=md0' even if that bootarg is not set\n");
    printf("     --kpatch-force-nand-writeable\t\tMake NAND writeable even in ramdisk boot\n");
    printf("     --kpatch-get-kernelbase-syscall\t\tSyscall 213 to return kernelbase\n");
    printf("     --kpatch-hardcode-bootargs ARGS\t\tSpecify kernel bootargs (to be hardcoded inside the kernel)\n");
    printf("     --kpatch-hardcode-boot-manifest-hash\tARGS Specify boot-manifest-hash (to be hardcoded inside the kernel)\n");
    printf("     --kpatch-i_can_has_debugger\t\tPatch i_can_has_debugger = 1\n");
    printf("     --kpatch-mount\t\t\t\tAllow mounting / as rw\n");
    printf("     --kpatch-no-ramdisk-detect\t\t\tPatch detection of 'rd=md0' in kernel\n");
    printf("     --kpatch-noemf\t\t\tDisable kernel EMF decryption\n");
    printf("     --kpatch-nuke-sandbox\t\t\tCompletely nuke sanbox by nulling ALL mac_policy_ops fields\n");
    printf("     --kpatch-root-from-sealed-apfs\t\tAllow rooting from sealed live APFS\n");
    printf("     --kpatch-sandbox\t\t\t\tNeuter sanbox by nulling common mac_policy_ops fields\n");
    printf("     --kpatch-setuid\t\t\t\tRe-add setuid functionality to kernel\n");
    printf("     --kpatch-tfp0\t\t\t\tAllow calling task_for_pid(0)\n");
    printf("     --kpatch-tfp-unrestrict\t\t\tAllow anyone calling task_for_pid()\n");
    printf("     --sn0wsn0w\t\t\t\t\tApply generic kernelpatches\n");

    printf("\n");
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    printf("%s\n",VERSION_STRING);
    printf("%s\n",img4tool::version());
    printf("%s\n",fragmentzip_version());
    printf("%s\n",libipatcher::version());
    retassure(libipatcher::has64bitSupport(), "This tool needs libipatcher compiled with 64bit support!");
    printf("\n");
    
    
    char *im4m = NULL;
    size_t im4mSize = 0;
    cleanup([&]{
        safeFree(im4m);
    });
    launchConfig cfg = {};
    std::string dryRunDevice;
    
    int optindex = 0;
    int opt = 0;
    
    libipatcher::pwnBundle bundle;
    std::string ipswUrl;

    const char *dryRunOutPath = NULL;
    const char *apticketPath = NULL;
    const char *buildid = NULL;
    const char *variant = NULL;
    uint64_t ecid = 0;
    bool waitForDevice = false;
    
    if (argc == 1){
        cmd_help();
        return -1;
    }
        
    while ((opt = getopt_long(argc, (char* const *)argv, "ht:B:e:wv:k:r:s:c:l:b:V:", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;
                
#define parsePatchConfig(name,val) if (curopt == name) cfg.val = PARSE_PATCH_CONFIG
                
                //device selectors
                if (curopt == "32bit") {
                    cfg.is32Bit = true;
                }else if (curopt == "dry-run") {
                    dryRunDevice = optarg;
                }else if (curopt == "dry-out") {
                    dryRunOutPath = optarg;
                }else if (curopt == "ota") {
                    cfg.isOtaFirmware = true;
                }
                //behavior config
                else if (curopt == "decrypt-devicetree") {
                    cfg.decrypt_devicetree = true;
                }else if (curopt == "iboot-as-ibec") {
                    cfg.boot_iboot_instead_of_ibec = true;
                }else if (curopt == "just-dfu") {
                    cfg.justDFU = true;
                }else if (curopt == "just-iboot") {
                    cfg.justiBoot = true;
                }else if (curopt == "nobootx") {
                    cfg.nobootx = true;
                }else if (curopt == "no-decrypt") {
                    cfg.noDecrypt = true;
                }else if (curopt == "no-sep") {
                    cfg.boot_no_sep = true;
                }else if (curopt == "srd") {
                    cfg.isSRD = true;
                }
                //Customized boot
                else if (curopt == "custom-component") {
                    parserCustomComponent(optarg, cfg);
                }else if (curopt == "ibec") {
                    cfg.iBECIm4p = readFile(optarg);
                }else if (curopt == "ibss") {
                    cfg.iBSSIm4p = readFile(optarg);
                }else if (curopt == "patch" || curopt == "fpatch") {
                    parserUserPatch(optarg, cfg, curopt == "fpatch");
                }else if (curopt == "send-all-components") {
                    cfg.sendAllComponents = true;
                }else if (curopt == "sreplace") {
                    parserStringReplacePatch(optarg, cfg);
                }
                //iBEC patches
                else if (curopt == "iboot-nopatch") {
                    cfg.iboot_nopatch = true;
                }
                else if (curopt == "iboot-no-sigpatch") {
                    cfg.no_iboot_sigpatch = true;
                }
                else if (curopt == "iboot-send-signed-sep") {
                    if (optarg) cfg.iboot_send_signed_sep = optarg;
                    else cfg.iboot_send_signed_sep.push_back('\0');
                }
                else parsePatchConfig("ipatch-add-rw-and-rx-mappings",iboot_add_rw_and_rx_mappings);
                else parsePatchConfig("ipatch-always-production",iboot_always_production);
                else parsePatchConfig("ipatch-always-sepfw-booted",iboot_always_sepfw_booted);
                else parsePatchConfig("ipatch-atv4k-enable-uart",iboot_atv4k_enable_uart);
                else if (curopt == "ipatch-cmdcall") {
                    cfg.cmdcall = optarg;
                }else if (curopt == "ipatch-cmdhandler") {
                    std::pair<std::string, uint64_t> lhandler;
                    lhandler.first = optarg;
                    auto pos = lhandler.first.find("=");
                    retassure(pos != std::string::npos, "failed parsing cmdhandler no '=' found. Expected format: name=value (go=0x41414141)");
                    retassure(lhandler.first.substr(pos+1,2) == "0x",  "failed parsing cmdhandler no '0x' found. Expected format: name=value (go=0x41414141)");
                    lhandler.second = strtoul_l(lhandler.first.substr(pos+1+2).c_str(), NULL, 16, LC_GLOBAL_LOCALE);
                    lhandler.first = lhandler.first.substr(0,pos);
                    retassure(lhandler.second, "failed parsing cmdhandler. Can't jump to 0x0");
                    cfg.cmdhandler.push_back(lhandler);
                }
                else parsePatchConfig("ipatch-dtre-debug-enable",iboot_dtre_debug_enable);
                else parsePatchConfig("ipatch-disable-wxn-el3",iboot_disable_wxn_el3);
                else parsePatchConfig("ipatch-no-force-dfu",iboot_no_force_dfu);
                else parsePatchConfig("ipatch-largepicture",iboot_largepicture);
                else parsePatchConfig("ipatch-memcpy",iboot_reboot_to_memcpy);
                else if (curopt == "ipatch-nvram-unlock"){
                    cfg.nobootx = true;
                    cfg.iboot_nvramUnlock = kPatchcfgYes;
               }
                else parsePatchConfig("ipatch-sep-force-local",iboot_sep_force_local);
                else parsePatchConfig("ipatch-sep-force-raw",iboot_sep_force_raw);
                else parsePatchConfig("ipatch-sep-skip-bpr",iboot_sep_skip_bpr);
                else parsePatchConfig("ipatch-sep-skip-lock",iboot_sep_skip_lock);
                else parsePatchConfig("ipatch-wtf-pwndfu",wtf_pwndfu);
                else if (curopt == "ra1nra1n") {
                    cfg.ra1nra1n = readFile(optarg);
                }
                //Kernel patches
                else if (curopt == "kernel-nopatch") {
                    cfg.kernel_nopatch = true;
                }
                else parsePatchConfig("kpatch-add-read-bpr",kpatch_add_read_bpr);
                else parsePatchConfig("kpatch-allow-uid",kpatch_allow_uid);
                else parsePatchConfig("kpatch-always-get-task-allow",kpatch_always_get_task_allow);
                else parsePatchConfig("kpatch-apfs-skip-authenticated-root-hash",kpatch_apfs_skip_authenticated_root);
                else parsePatchConfig("kpatch-codesignature",kpatch_codesig);
                else parsePatchConfig("kpatch-force-boot-ramdisk",kpatch_force_boot_ramdisk);
                else parsePatchConfig("kpatch-force-nand-writeable",kpatch_force_nand_writeable);
                else parsePatchConfig("kpatch-get-kernelbase-syscall",kpatch_get_kernelbase_syscall);
                else if (curopt == "kpatch-hardcode-bootargs") {
                    cfg.kernelHardcodeBootargs = optarg;
                }else if (curopt == "kpatch-hardcode-boot-manifest-hash") {
                    size_t len = strlen(optarg);
                    if (len & 1){
                        error("Failed reading hexbytes!");
                        return -1;
                    }
                    for (size_t i = 0; i<len; i+=2) {
                        uint32_t byte = 0;
                        assure(sscanf(&optarg[i], "%02x",&byte) == 1);
                        cfg.kernelHardcoderoot_ticket_hash.push_back((uint8_t)byte);
                    }
                }
                else parsePatchConfig("kpatch-i_can_has_debugger",kpatch_i_can_has_debugger);
                else parsePatchConfig("kpatch-mount",kpatch_mount);
                else parsePatchConfig("kpatch-no-ramdisk-detect",kpatch_no_ramdisk_detect);
                else parsePatchConfig("kpatch-noemf",kpatch_noemf);
                else parsePatchConfig("kpatch-nuke-sandbox",kpatch_nuke_sandbox);
                else parsePatchConfig("kpatch-root-from-sealed-apfs",kpatch_root_from_sealed_apfs);
                else parsePatchConfig("kpatch-sandbox",kpatch_sandbox);
                else parsePatchConfig("kpatch-setuid",kpatch_setuid);
                else parsePatchConfig("kpatch-tfp0",kpatch_tfp0);
                else parsePatchConfig("kpatch-tfp-unrestrict",kpatch_tfp_unrestrict);
                else if (curopt == "sn0wsn0w") {
                    cfg.doJailbreakPatches = true;
                }
                break;
            }
                
            case 'b': // long option: "boot-args"
                cfg.bootargs = optarg;
                break;
            case 'B': // long option: "buildid"
                buildid = optarg;
                break;
            case 'c':// long option: "trustcache"
                cfg.trustcache = readFile(optarg);
                break;
            case 'e': // long option: "buildid"
                if (strncmp(optarg, "0x", 2) == 0) {
                    ecid = strtoul_l(optarg, NULL, 16, LC_GLOBAL_LOCALE);
                }else{
                    ecid = strtoul_l(optarg, NULL, 10, LC_GLOBAL_LOCALE);
                }
                break;
            case 'k':// long option: "kernel"
                cfg.kernelIm4p = readFile(optarg);
                break;
            case 'l':// long option: "logo"
                cfg.bootlogoIm4p = readFile(optarg);
                break;
            case 'r':// long option: "ramdisk"
                cfg.ramdiskIm4p = readFile(optarg);
                break;
            case 's':// long option: "sep"
                cfg.sepIm4p = readFile(optarg);
                break;
            case 't': // long option: "apticket"
                apticketPath = optarg;
                break;
            case 'V':// long option: "variant"
                variant = optarg;
                break;
            case 'w':// long option: "wait"
                waitForDevice = true;
                break;
            case 'h': // long option: "help"
                cmd_help();
                return 0;
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        
        ipswUrl = argv[0];
    }
    
    if (cfg.justiBoot) {
        printf("just-boot option enabled! Will return once iBoot was reached\n");
    }else if (cfg.nobootx) {
        printf("nobootx option enabled! Run \"bootx\" to boot device manually\n");
    }
    
    
    retassure(buildid || ipswUrl.size(), "Missing argument: need either buildid or path to ipsw");
    
    iOSDevice device(ecid, waitForDevice, dryRunDevice, dryRunOutPath ? dryRunOutPath : "");
    std::string model = device.getDeviceProductType();
    
    if (ipswUrl.size()){
        if (ipswUrl.substr(0,4) != "http") {
            retassure(!access(ipswUrl.c_str(), F_OK),"ERROR: Firmware file %s does not exist.\n", ipswUrl.c_str());
            printf("Got local ipsw path=%s\n",ipswUrl.c_str());
            ipswUrl.insert(0, "file://");
        }
    }else {
        printf("No IPSW specified, getting URL to ipsw by buildid\n");
        try {
            bundle = libipatcher::getPwnBundleForDevice(model, buildid, device.getDeviceCPID());
        } catch (tihmstar::exception &e) {
            printf("libipatcher::getPwnBundleForDevice failed with error:\n");
            e.dump();
            reterror("Failed to get firmware url. Please download ipsw and manually specify path");
        }
        printf("Found build %s at %s\n",buildid,bundle.firmwareUrl.c_str());
        ipswUrl = bundle.firmwareUrl.c_str();
    }
    
    if (apticketPath) {
        retassure((im4m = im4mFormShshFile(apticketPath, &im4mSize, NULL)) || cfg.isSRD, "Failed to load APTicket");
        if (im4mSize) {
            launchDevice(device, ipswUrl, cfg, {im4m,im4mSize}, variant ? variant : "");
        }else{
            launchDevice(device, ipswUrl, cfg, {}, variant ? variant : "");
        }
    }else{
        launchDevice(device, ipswUrl, cfg, {}, variant ? variant : "");
    }
    
    return 0;
}
