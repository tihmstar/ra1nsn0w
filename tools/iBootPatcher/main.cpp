//
//  main.cpp
//  iBootPatcher
//
//  Created by tihmstar on 22.09.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#include "../../include/ra1nsn0w/ra1nsn0w_patch.hpp"
#include "../../include/ra1nsn0w/ra1nsn0w_plugins.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <libfwkeyfetch/libfwkeyfetch.hpp>

extern "C"{
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

void cmd_help(){
    printf(
           "\n"
           "Usage: iBootPatcher [OPTIONS] <input file> <output file>\n" \
           "Tool for patching iBoot\n" \
           "      --32bit\t\t\t\t\tUse 32bit patchfinder instead of 64bit\n" \
           "      --iv\t\t\t\t\tIV  for decrypting iBoot\n"
           "      --key\t\t\t\t\tKey for decrypting iBoot\n"
           "\n"
    );
    const char *helpScreenGeneral = ra1nsn0w::getCmdHelpStringGeneral();
    printf("%s",helpScreenGeneral);
    const char *helpScreeniBoot = ra1nsn0w::getCmdHelpStringiBoot();
    printf("%s",helpScreeniBoot);
    const char *helpScreenPlugins = ra1nsn0w::getCmdHelpStringPlugins();
    printf("%s",helpScreenPlugins);
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s",VERSION_STRING);
#ifdef WITH_PLUGIN_SUPPORT
    info("Plugin support: YES");
#else
    info("Plugin support: NO");
#endif //WITH_PLUGIN_SUPPORT

    launchConfig cfg = {};
    struct bootconfig bcfg ={
        .launchcfg = &cfg
    };
    
    libfwkeyfetch::fw_key keys = {};
    
    int optindex = 0;
    int opt = 0;
    
    const char *inputFile = NULL;
    const char *outputFile = NULL;
    const char *exportPatchesPath = NULL;
    
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
                
                if (curopt == "export-patches") {
                    exportPatchesPath = optarg;
                } else if (curopt == "iv") {
                    strncpy(keys.iv, optarg, sizeof(keys.iv));
                } else if (curopt == "key") {
                    strncpy(keys.key, optarg, sizeof(keys.key));
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
            case 'h': // long option: "help"
                cmd_help();
                return 0;
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (argc-optind >= 1) {
        inputFile = argv[optind];
    }

    if (argc-optind >= 2) {
        outputFile = argv[optind+1];
    }

    if (!inputFile) {
        error("Missing input file!");
        return 2;
    }

    info("Reading input file '%s'",inputFile);

    auto iBoot = tihmstar::readFile(inputFile);
    info("Patching File...");

    {
        tihmstar::Mem patchediBoot;

        try {
            retassure(patchFunciBoot(iBoot.data(), iBoot.size(), &bcfg) == 0,"Failed to patch file, maybe not raw?");
            info("Successfully patched RAW iBoot");
            patchediBoot = iBoot;
        } catch (tihmstar::exception &e) {
#ifdef DEBUG
            e.dump();
            debug("Failed to perform patch on raw file, retrying on packed file");
#endif
            if (!patchediBoot.size()){
                try {
                    auto pp = patchIMG4(iBoot.data(), iBoot.size(), keys.iv, keys.key, "iBoot", (int(*)(char*,size_t,void*))patchFunciBoot, (void*)&bcfg);
                    patchediBoot = {(const void*)pp.buf(), pp.size()};
                } catch (tihmstar::exception &e) {
                    error("Failed patching IMG4 files with error:\n%s",e.dumpStr().c_str());
                }
            }
            if (!patchediBoot.size()){
                try {
                    patchediBoot = patchIMG3(iBoot.data(), iBoot.size(), keys.iv, keys.key, "iBoot", (int(*)(char*,size_t,void*))patchFunciBoot, (void*)&bcfg);
                } catch (tihmstar::exception &e) {
                    error("Failed patching IMG3 files with error:\n%s",e.dumpStr().c_str());
                }
            }
            if (patchediBoot.size()){
                info("Successfully patched packed iBoot");
            }else{
                error("Failed patching iBoot");
                return 5;
            }
        }

        if (exportPatchesPath) {
            exportPatchesToJson(bcfg.appliedPatches, exportPatchesPath);
            info("Patches exported to '%s'",exportPatchesPath);
        }
        
        if (outputFile) {
            writeFile(outputFile, patchediBoot.data(), patchediBoot.size());
            info("Wrote patched file to '%s'",outputFile);
        }else{
            warning("Not writing output to file, because no path was specified!");
        }
    }
    
    return 0;
}
