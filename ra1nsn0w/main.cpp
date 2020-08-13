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
#include "ra1nsn0w.hpp"
#include "iOSDevice.hpp"
#include <string.h>
#include <algorithm>
#include <cctype>
#include <string>

extern "C"{
#include <libfragmentzip/libfragmentzip.h>
#include <plist/plist.h>
};

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

static struct option longopts[] = {
    { "help",                   no_argument,            NULL, 'h' },
    { "apticket",               required_argument,      NULL, 't' },
    { "buildid",                required_argument,      NULL, 'B' },
    { "udid",                   required_argument,      NULL, 'u' },
    { "nobootx",                no_argument,            NULL,  0  },
    { "boot-args",              required_argument,      NULL, 'b' },
    { "cmdhandler",             required_argument,      NULL,  1  },
    { "nvram-unlock",           no_argument,            NULL, 'n' },
    { "kernel",                 required_argument,      NULL, 'k' },
    { "ramdisk",                required_argument,      NULL, 'r' },
    { "dump-apticket",          required_argument,      NULL,  2  },
    { "ra1nra1n",               required_argument,      NULL,  3  },
    { "sn0wsn0w",               no_argument,            NULL,  4  },
    { "patch",                  required_argument,      NULL,  5  },
    { "just-iboot",             no_argument,            NULL,  6  },
    { "add-rw-and-rx-mappings", no_argument,            NULL,  7  },
    { NULL, 0, NULL, 0 }
};

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

void parserUserPatch(std::string userpatch, launchConfig &cfg){
    printf("Parsing custom user patch \"%s\"\n",userpatch.c_str());
    ssize_t colunpos = 0;
    uint32_t component = 0;

    assure((colunpos = userpatch.find(":")) != std::string::npos);

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

        std::string pAddr = patchstr.substr(0,commaPos);
        std::string pPatch = patchstr.substr(commaPos+1,nextPatchPos);
        
        uint64_t addr = 0;
        assure(sscanf(pAddr.c_str(), "0x%llx",&addr) == 1);
        
        patchBytes = (uint8_t*)malloc(pPatch.size());
        
        for (size_t i = 0; i<pPatch.size(); i+=2) {
            uint32_t byte = 0;
            assure(sscanf(&pPatch.c_str()[i], "%02x",&byte) == 1);
            patchBytes[i/2] = (uint8_t)byte;
        }
        
        offsetfinder64::patch p{addr,patchBytes,pPatch.size()/2};

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

void cmd_help(){
    printf("Usage: ra1nsn0w [OPTIONS] [IPSW]\n");
    printf("Multipurpose tool for launching custom bootchain\n\n");
    
    printf("Device selectors:\n");
    printf("  -h, --help\t\t\tDisplays this helpscreen\n");
    printf("  -t, --apticket PATH\t\tApticket use for bypassing sigchecks (Note: current sigcheck patches require an APTicket)\n");
    printf("  -B  --buildid BUILDID\t\tspecific buildid instead of iOS ipsw path\n");
    printf("  -e, --ecid ECID\t\tTarget specific device by its device ECID\n");

    printf("\nBehavior config:\n");
    printf("     --nobootx\t\t\tDon't run \"bootx\" command\n");
    printf("     --just-iboot\t\tOnly boot to iBoot, do not send anything to it\n");

    printf("\niBEC patches:\n");
    printf("  -b, --boot-args ARGS\t\tSpecify kernel bootargs\n");
    printf("      --cmdhandler NAME=VALUE\tPatch command NAME to jump to VALUE\n");
    printf("            (Example --cmdhandler go=0x41414141 makes go command jump to address 0x41414141)\n");
    printf("  -n, --nvram-unlock\t\tAllows reading and writing all nvram vars\n");
    printf("      --add-rw-and-rx-mappings\tSets iBoot block writeable at 0x2000000 and loadaddr block executable at 0x4000000\n");

    printf("\nKernel patches:\n");
    printf("     --sn0wsn0w\tApply generic kernelpatches\n");


    printf("\nCustomized boot:\n");
    printf("  -k, --kernel <path>\t\tManually specify a kernel.im4p to boot\n");
    printf("  -r, --ramdisk <path>\t\tManually specify a ramdisk.im4p to boot\n");
    printf("      --patch=<component>:<addr1>,<patch1>;<addr1>,<patch2>...\tManually specify a patch to a component\n");
    
    printf("\nTools:\n");
    printf("     --dump-apticket <path>\tDumps APTicket and writes shsh2 file to path\n");
    printf("     --ra1nra1n <path>\t\tExecute payload before jumping to kernel\n");

    printf("\n");
}

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
    bool toolsIsSelected = false;
    launchConfig cfg = {};

    int optindex = 0;
    int opt = 0;
    
    libipatcher::pwnBundle bundle;
    std::string ipswUrl;

    const char *apticketPath = NULL;
    const char *buildid = NULL;
    uint64_t ecid = 0;

    const char *shshDumpOutPath = NULL;
    
    if (argc == 1){
        cmd_help();
        return -1;
    }
    
    while ((opt = getopt_long(argc, (char* const *)argv, "ht:B:e:b:nk:r:", longopts, &optindex)) > 0) {
        switch (opt) {
            case 't': // long option: "apticket"
                apticketPath = optarg;
                break;
            case 'B': // long option: "buildid"
                buildid = optarg;
                break;
            case 'e': // long option: "buildid"
                if (strncmp(optarg, "0x", 2) == 0) {
                    ecid = strtoul_l(optarg, NULL, 16, LC_GLOBAL_LOCALE);
                }else{
                    ecid = strtoul_l(optarg, NULL, 10, LC_GLOBAL_LOCALE);
                }
                break;
            case 'b': // long option: "boot-args"
                cfg.bootargs = optarg;
                break;
            case 0: // long option: "nobootx"
                cfg.nobootx = true;
                break;
            case 'n': // long option: "nvram-unlock"
                cfg.nobootx = true;
                cfg.nvramUnlock = true;
                break;
            case 3:
                retassure(!toolsIsSelected, "only one tools option can be used at a time!");
                toolsIsSelected = true;
                cfg.ra1nra1nPath = optarg;
                break;
            case 4:
                cfg.doJailbreakPatches = true;
                break;
            case 1: // long option: "cmdhandler"
                {
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
                break;
            case 'k':// long option: "kernel"
                cfg.kernelIm4pPath = optarg;
                break;
            case 'r':// long option: "ramdisk"
                cfg.ramdiskIm4pPath = optarg;
                break;
            case 2:
                shshDumpOutPath = optarg;
                break;
            case 5:
                parserUserPatch(optarg, cfg);
                break;
            case 6:
                cfg.justiBoot = true;
                break;
            case 7: //add-rw-and-rx-mappings
                cfg.add_rw_and_rx_mappings = true;
                break;

            case 'h': // long option: "help"
                 //intentionally fall through
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
    retassure(apticketPath, "Missing argument: APTicket is required for sigchk bypass");
    
    retassure(im4m = im4mFormShshFile(apticketPath, &im4mSize, NULL), "Failed to load APTicket");
    
    iOSDevice device(ecid);
    std::string model = device.getDeviceProductType();
    
    if (ipswUrl.size()){
        retassure(!access(ipswUrl.c_str(), F_OK),"ERROR: Firmware file %s does not exist.\n", ipswUrl.c_str());
        printf("Got local ipsw path=%s\n",ipswUrl.c_str());
        ipswUrl.insert(0, "file://");
    }else {
        printf("No IPSW specified, getting URL to ipsw by buildid\n");
        try {
            bundle = libipatcher::getPwnBundleForDevice(model,buildid);
        } catch (tihmstar::exception &e) {
            printf("libipatcher::getPwnBundleForDevice failed with error:\n");
            e.dump();
            reterror("Failed to get firmware url. Please download ipsw and manually specify path");
        }
        printf("Found build %s at %s\n",buildid,bundle.firmwareUrl.c_str());
        ipswUrl = bundle.firmwareUrl.c_str();
    }
    
    if (toolsIsSelected) {
        printf("tools selected!\n");
        if (cfg.ra1nra1nPath) {
            printf("ra1nra1n option detected! Discarding user options and loading predefined launch config.\n");
            const char * tmp = cfg.ra1nra1nPath;
            cfg = {};
            cfg.ra1nra1nPath = tmp;
        }else if (shshDumpOutPath) {
            printf("apticketdump option detected! Discarding user options and loading predefined launch config.\n");
            cfg = {};
            cfg.apticketdump = true;
            cfg.nvramUnlock = true;
            reterror("not implemented!");
        }
    }
    
    
    launchDevice(device, ipswUrl, {im4m, im4mSize}, cfg);
    
    if (shshDumpOutPath) {
        dumpAPTicket(device, shshDumpOutPath);
    }
    
    return 0;
}

int main(int argc, const char * argv[]) {
#ifdef DEBUG
    return main_r(argc, argv);
#else
    try {
        return main_r(argc, argv);
    } catch (tihmstar::exception &e) {
        printf("%s: failed with exception:\n",PACKAGE_NAME);
        e.dump();
        return e.code();
    }
#endif
}
