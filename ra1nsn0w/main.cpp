//
//  main.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "../include/ra1nsn0w/ra1nsn0w.hpp"
#include "../include/ra1nsn0w/ra1nsn0w_plugins.hpp"
#include "../include/ra1nsn0w/iOSDevice.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <libipatcher/libipatcher.hpp>
#include <img4tool/img4tool.hpp>

extern "C"{
#include <libfragmentzip/libfragmentzip.h>
#include <plist/plist.h>
};

#include <algorithm>
#include <cctype>

#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <getopt.h>

#ifdef WITH_PLUGIN_SUPPORT
#   include <dirent.h>
#   include <dlfcn.h>
#endif //WITH_PLUGIN_SUPPORT

#ifndef HAVE_STRTOUL_L
#define strtoul_l _strtoul_l
#endif

#ifndef LC_GLOBAL_LOCALE
# define LC_GLOBAL_LOCALE ((_locale_t)-1) //this is for windows :/
#endif

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

plist_t readPlistFromFile(const char *filePath){
    auto f = readFile(filePath);
    plist_t plist = NULL;
    plist_from_memory((const char*)f.data(), (uint32_t)f.size(), &plist, NULL);
    return plist;
}

char *im4mFormShshFile(const char *shshfile, size_t *outSize, char **generator){
    plist_t shshplist = NULL;
    cleanup([&]{
        safeFreeCustom(shshplist, plist_free);
    });
    shshplist = readPlistFromFile(shshfile);

    
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
    return im4msize ? im4m : NULL;
}

void cmd_help(){
    const char *helpScreen = ra1nsn0w::getCmdHelpString();
    printf("%s",helpScreen);
}

void exportPatchesToJson(std::map<uint32_t,std::vector<patchfinder::patch>> patches, const char *outfilePath){
    plist_t p_patches = NULL;
    char *json = NULL;
    cleanup([&]{
        safeFree(json);
        safeFreeCustom(p_patches, plist_free);
    });
    uint32_t jsonSize = 0;
    p_patches = plist_new_dict();
    for (auto cp : patches) {
        plist_t p_component = NULL;
        cleanup([&]{
            safeFreeCustom(p_component, plist_free);
        });
        char componentName[8] = {};
        memcpy(componentName, &cp.first, 4);
        p_component = plist_new_dict();

        for (auto p : cp.second) {
            char location[0x20] = {};
            char curbyte[8] = {};
            std::string patch;
            snprintf(location, sizeof(location), "0x%016llx",p._location);
            for (int i=0; i<p.getPatchSize(); i++) {
                snprintf(curbyte, sizeof(curbyte), "%02x",((unsigned char*)p.getPatch())[i]);
                patch += curbyte;
            }
            plist_dict_set_item(p_component, location, plist_new_string(patch.c_str()));
        }
        plist_dict_set_item(p_patches, componentName, p_component);p_component = NULL;
    }
    plist_to_json(p_patches, &json, &jsonSize, 1);
    tihmstar::writeFile(outfilePath, json, jsonSize);
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s",VERSION_STRING);
    info("%s",img4tool::version());
    info("%s",fragmentzip_version());
    info("%s",libipatcher::version());
    retassure(libipatcher::has64bitSupport(), "This tool needs libipatcher compiled with 64bit support!");
#ifdef WITH_PLUGIN_SUPPORT
    info("Plugin support: YES");
#else
    info("Plugin support: NO");
#endif //WITH_PLUGIN_SUPPORT

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

    const char *exportPatchesPath = NULL;
    const char *dryRunOutPath = NULL;
    const char *apticketPath = NULL;
    const char *buildid = NULL;
    const char *variant = NULL;
    uint64_t ecid = 0;
    bool waitForDevice = false;
    
#ifdef WITH_PLUGIN_SUPPORT
    if (const char *pluginPath = getenv("RA1NSN0W_PLUGIN_DIRECTORY")) {
        DIR* pdir = NULL;
        cleanup([&]{
            safeFreeCustom(pdir, closedir);
        });
        pdir = opendir(pluginPath);
        std::string ppath = pluginPath;
        if (ppath.back() != '/') ppath += '/';
        if (!pdir){
            error("Failed to opendir '%s'",pluginPath);
        }else{
            while (struct dirent *file = readdir(pdir)) {
                if (!strncmp (file->d_name, ".", 1)) continue;
                if (file->d_type != DT_REG) continue;
                std::string fullpath = ppath + file->d_name;
                void *handle = dlopen(fullpath.c_str(), RTLD_NOW);
                if (handle) info("Loaded plugin '%s'",fullpath.c_str());
                else error("Trying to loading plugin '%s' failed with reason '%s'",fullpath.c_str(),dlerror());
            }
        }
    }
#endif //WITH_PLUGIN_SUPPORT

    if (argc == 1){
        cmd_help();
        return -1;
    }
        
    const struct option *longopts = ra1nsn0w::getLongOpts();
    const char *shortopts = ra1nsn0w::getShortOpts();
    
    while ((opt = getopt_long(argc, (char* const *)argv, shortopts, longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;
                
                if (curopt == "dry-run") {
                    dryRunDevice = optarg;
                } else if (curopt == "dry-out") {
                    dryRunOutPath = optarg;
                } else if (curopt == "export-patches") {
                    exportPatchesPath = optarg;
                } else if (curopt == "keys-zip") {
                    if (strncmp(optarg, "http", 4) != 0) {
                        //local path?
                        if (!tihmstar::fileExists(optarg)) {
                            error("Unable to locate key zipfile at '%s'\n", optarg);
                            return -6;
                        }
                        cfg.customKeysZipUrl = "file://";
                    }
                    cfg.customKeysZipUrl += optarg;
                } else if (!ra1nsn0w::parseArgument(cfg, curopt, optarg)) {
                    error("Unknown longopt '%s'",curopt.c_str());
                    return -5;
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
    std::map<uint32_t,std::vector<patchfinder::patch>> appliedPatches;
    
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
            appliedPatches = launchDevice(device, ipswUrl, cfg, {im4m,im4mSize}, variant ? variant : "");
        }else{
            appliedPatches = launchDevice(device, ipswUrl, cfg, {}, variant ? variant : "");
        }
    }else{
        appliedPatches = launchDevice(device, ipswUrl, cfg, {}, variant ? variant : "");
    }

    if (exportPatchesPath) {
        exportPatchesToJson(appliedPatches, exportPatchesPath);
        info("Patches exported to '%s'",exportPatchesPath);
    }
    
    return 0;
}
