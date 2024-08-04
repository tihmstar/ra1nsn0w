//
//  ra1nsn0w.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "../include/ra1nsn0w/ra1nsn0w.hpp"
#include "../include/ra1nsn0w/ra1nsn0w_plugins.hpp"
#include <libgeneral/macros.h>
#include <plist/plist.h>
#include <libipatcher/libipatcher.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder32.hpp>
#include <img3tool/img3tool.hpp>
#include <tsschecker/tsschecker.hpp>
#include <tsschecker/TssRequest.hpp>
#include <tsschecker/TSSException.hpp>
#include <sys/stat.h>
#include <string.h>

extern "C"{
#include <libfragmentzip/libfragmentzip.h>
};

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#endif

#ifdef HAVE_IMG1TOOL
#include <img1tool/img1tool.hpp>
#endif

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;


struct bootconfig{
    const launchConfig *launchcfg;
    bool didProcessKernelLoader;
    bool skipiBEC;
    uint32_t curPatchComponent;
    std::map<uint32_t,std::vector<patchfinder::patch>> appliedPatches;
};

#define addKernelpatch(cfgname, funcname, funcstring) \
                    if (cfg.cfgname) { \
                        if ((cfg.cfgname & (kPatchcfgYes | kPatchcfgMayFail)) \
                            || (cfg.is32Bit && (cfg.cfgname & (kPatchcfg32Yes | kPatchcfg32MayFail))) \
                            || (!cfg.is32Bit && (cfg.cfgname & (kPatchcfg64Yes | kPatchcfg64MayFail))) ){\
                            info("Kernel: Adding " funcstring " patch...\n"); \
                            try { \
                                auto patch = kpf->funcname(); \
                                patches.insert(patches.end(), patch.begin(), patch.end()); \
                            } catch (tihmstar::exception &e) { \
                                if ((cfg.cfgname & kPatchcfgMayFail) \
                                    || (cfg.is32Bit && (cfg.cfgname & kPatchcfg32MayFail)) \
                                    || (!cfg.is32Bit && (cfg.cfgname & kPatchcfg64MayFail)) )\
                                        warning("Patch " funcstring " failed with error=%d (%s) but was marked as optional. Proceeding without...",e.code(),e.what()); \
                                else throw; \
                            } \
                        }\
                    }

#define addiBootpatch(cfgname, funcname, funcstring) addiBootpatchCustom(cfgname, funcname, /**/, funcstring)
#define addiBootpatchCustom(cfgname, funcname, arg, funcstring) \
                    if (cfg->cfgname) { \
                        if ((cfg->cfgname & (kPatchcfgYes | kPatchcfgMayFail)) \
                            || (cfg->is32Bit && (cfg->cfgname & (kPatchcfg32Yes | kPatchcfg32MayFail))) \
                            || (!cfg->is32Bit && (cfg->cfgname & (kPatchcfg64Yes | kPatchcfg64MayFail))) ){\
                            info("iBoot: Adding " funcstring " patch..."); \
                            try { \
                                auto patch = ibpf->funcname(arg); \
                                patches.insert(patches.end(), patch.begin(), patch.end()); \
                            } catch (tihmstar::exception &e) { \
                                if ((cfg->cfgname & kPatchcfgMayFail) \
                                    || (cfg->is32Bit && (cfg->cfgname & kPatchcfg32MayFail)) \
                                    || (!cfg->is32Bit && (cfg->cfgname & kPatchcfg64MayFail)) )\
                                        warning("Patch " funcstring " failed with error=%d (%s) but was marked as optional. Proceeding without...",e.code(),e.what()); \
                                else throw; \
                            } \
                        }\
                    }


#pragma mark helpers


static void printline(int percent){
    printf("%03d [",percent);for (int i=0; i<100; i++) putchar((percent >0) ? ((--percent > 0) ? '=' : '>') : ' ');
    printf("]");
}

static void fragmentzip_callback(unsigned int progress){
    printf("\x1b[A\033[J"); //clear 2 lines
    printline((int)progress);
    printf("\n");
}

static plist_t readPlistFromFile(const char *filePath){
    FILE *f = fopen(filePath,"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);

    size_t fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc(fSize);
    if (buf) fread(buf, fSize, 1, f);
    fclose(f);

    plist_t plist = NULL;
    plist_from_memory(buf, (uint32_t)fSize, &plist, NULL);
    free(buf);
    return plist;
}

static char *im4mFormShshFile(const char *shshfile, size_t *outSize){
    plist_t shshplist = readPlistFromFile(shshfile);
    if (!shshplist) return NULL;
    plist_t ticket = plist_dict_get_item(shshplist, "ApImg4Ticket");

    char *im4m = 0;
    uint64_t im4msize=0;
    plist_get_data_val(ticket, &im4m, &im4msize);
    if (outSize) {
        *outSize = im4msize;
    }
    plist_free(shshplist);
    return im4msize ? im4m : NULL;
}

#pragma mark ra1nsn0w

img4tool::ASN1DERElement img4FromIM4PandIM4M(const img4tool::ASN1DERElement &im4p, const img4tool::ASN1DERElement &im4m){
    img4tool::ASN1DERElement img4 = img4tool::getEmptyIMG4Container();
    img4 = img4tool::appendIM4PToIMG4(img4, im4p);
    img4 = img4tool::appendIM4MToIMG4(img4, im4m);
    return img4;
}


int iBootPatchFunc(char *file, size_t size, void *param){
    patchfinder::ibootpatchfinder *ibpf = nullptr;
    cleanup([&]{
        safeDelete(ibpf);
    });

    bootconfig *bcfg = (bootconfig *)param;
    const launchConfig *cfg = bcfg->launchcfg;
    std::vector<patchfinder::patch> patches;

    if (cfg->is32Bit) {
        ibpf = patchfinder::ibootpatchfinder32::make_ibootpatchfinder32(file,size);
    }else{
        ibpf = patchfinder::ibootpatchfinder64::make_ibootpatchfinder64(file,size);
    }
    
    if (cfg->no_iboot_sigpatch){
        warning("Skipping iBoot sigpatch! Device WILL NOT BOOT past this bootloader if patches aren't applied manually!!!!");
    }else{
        info("iBoot: Adding sigcheck patch...");
        auto patch = ibpf->get_sigcheck_patch();
        patches.insert(patches.end(), patch.begin(), patch.end());
    }
    
    addiBootpatch(wtf_pwndfu, get_wtf_pwndfu_patch, "wtf_pwndfu")

    if (ibpf->has_recovery_console()) {
        bcfg->didProcessKernelLoader = true;
        
        {
            try {
                info("iBoot: Adding \"recovery mode\"->\"ra1nsn0w mode\" patch...");
                auto patch = ibpf->get_replace_string_patch("recovery mode", "ra1nsn0w mode");
                patches.insert(patches.end(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                warning("Failed to add \"recovery mode\"->\"ra1nsn0w mode\" patch with error=%d (%s). Ignoring this and continueing anyways...",e.code(),e.what());
                e.dump();
            }
        }
        
        addiBootpatch(iboot_add_rw_and_rx_mappings, get_rw_and_x_mappings_patch_el1, "add_rw_and_rx_mappings")
        addiBootpatch(iboot_sep_skip_lock, get_tz0_lock_patch, "get_tz0_lock_patch")
        addiBootpatch(iboot_sep_skip_bpr, get_skip_set_bpr_patch, "get_skip_set_bpr_patch")
        addiBootpatch(iboot_sep_force_local, get_force_septype_local_patch, "get_force_septype_local_patch")
        addiBootpatch(iboot_sep_force_raw, get_sep_load_raw_patch, "get_sep_load_raw_patch")
        addiBootpatch(iboot_largepicture, get_large_picture_patch, "get_large_picture_patch")
        addiBootpatch(iboot_atv4k_enable_uart, get_atv4k_enable_uart_patch, "get_atv4k_enable_uart_patch")
        addiBootpatch(iboot_always_production, get_always_production_patch, "get_always_production_patch")
        addiBootpatch(iboot_always_sepfw_booted, get_always_sepfw_booted_patch, "get_always_sepfw_booted_patch")
        addiBootpatch(iboot_no_force_dfu, get_no_force_dfu_patch, "get_no_force_dfu_patch")
        addiBootpatch(iboot_dtre_debug_enable, get_debug_enabled_patch, "get_debug_enabled_patch")

        
        if (cfg->root_ticket_hash.size())            {
            info("iBoot: Adding root_ticket_hash patch...");
            auto patch = ibpf->set_root_ticket_hash(cfg->root_ticket_hash.data(), cfg->root_ticket_hash.size());
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        if (cfg->ra1nra1n.size()){
            {
                info("iBoot: Adding ra1nra1n patch...");
                auto patch = ibpf->get_ra1nra1n_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            {
                info("iBoot: Adding replace_reboot_with_memcpy patch...");
                auto patch = ibpf->replace_cmd_with_memcpy("reboot");
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
        }else{
            addiBootpatchCustom(iboot_reboot_to_memcpy, replace_cmd_with_memcpy, "reboot", "replace_reboot_with_memcpy")
        }

        if (cfg->bootargs.size()) {
            info("iBoot: Adding boot-arg patch (%s) ...",cfg->bootargs.c_str());
            auto patch = ibpf->get_boot_arg_patch(cfg->bootargs.c_str());
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        if (cfg->cmdhandler.size()){
            for (auto handler : cfg->cmdhandler) {
                info("iBoot: Adding cmdhandler patch (%s=0x%016llx) ...",handler.first.c_str(),handler.second);
                auto patch = ibpf->get_cmd_handler_patch(handler.first.c_str(),handler.second);
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
        }
        
        if (cfg->cmdcall.size()) {
            info("iBoot: Adding cmdcall patch (%s) ...",cfg->cmdcall.c_str());
            auto patch = ibpf->get_cmd_handler_callfunc_patch(cfg->cmdcall.c_str());
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        addiBootpatch(iboot_nvramUnlock, get_unlock_nvram_patch, "nvram_unlock")
    }
    
    if (cfg->replacePatches.find(bcfg->curPatchComponent) != cfg->replacePatches.end()) {
        auto replacePatches = cfg->replacePatches.at(bcfg->curPatchComponent);
        for (auto &r : replacePatches) {
            auto patch = ibpf->get_replace_string_patch(r.first, r.second);
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        info("Inserted replacepatches for current component!");
    }

    try {
        auto userpatches = cfg->userPatches.at(bcfg->curPatchComponent); //check if we have custom user patches for this component
        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
        info("Inserted custom userpatches for current component!");
    } catch (...) {
        //
    }
    
    for (auto p : bcfg->launchcfg->activePlugins) {
        auto ppatches = p.second->patcher(bcfg->curPatchComponent, file, size);
        patches.insert(patches.end(), ppatches.begin(), ppatches.end());
    }
    
    /* ---------- Applying collected patches ---------- */
    bcfg->appliedPatches[bcfg->curPatchComponent] = patches;
    info("iBoot: Applying patches...");
    for (auto p : patches) {
        uint64_t off = (uint64_t)(p._location - ibpf->find_base());
#ifdef DEBUG
        printf("iBoot: Applying patch=%p : ",(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
#endif
        memcpy(&file[off], p.getPatch(), p.getPatchSize());
    }
    info("iBoot: Patches applied!");
    return 0;
}

tihmstar::Mem downloadComponent(fragmentzip_t *fzinfo, std::string path, bool isOta){
    char *buf = NULL;
    cleanup([&]{
        safeFree(buf);
    });
    size_t bufSize = 0;
    if (isOta) path = "AssetData/boot/" + path;
    info("Loading %s ...",path.c_str());
    retassure(!fragmentzip_download_to_memory(fzinfo, path.c_str(), &buf, &bufSize, fragmentzip_callback),"Failed to load '%s'",path.c_str());
    {
        Mem ret = {buf,bufSize}; buf = NULL; bufSize = 0;
        return ret;
    }
}

std::map<uint32_t,std::vector<patchfinder::patch>> ra1nsn0w::launchDevice(iOSDevice &idev, std::string firmwareUrl, const launchConfig &cfg, img4tool::ASN1DERElement im4m, std::string variant){
    bootconfig bootcfg = {&cfg};
    fragmentzip_t *fzinfo = NULL;
    char *buildmanifestBuf = NULL;
    size_t buildmanifestBufSize = 0;
    plist_t buildmanifest = NULL;

    char *buildnum = NULL;
    uint32_t buildMajorVersion = 0;

    cleanup([&]{
        safeFree(buildnum);
        safeFreeCustom(buildmanifest,plist_free);
        safeFree(buildmanifestBuf);
        safeFreeCustom(fzinfo,fragmentzip_close);
    });
    plist_t buildidentity = NULL;
    plist_t pBuildnum = NULL;
    libipatcher::fw_key iBSSKeys = {};
    libipatcher::fw_key iBECKeys = {};
    libipatcher::fw_key kernelKeys = {};
    
    std::string ibssPath;
    std::string ibecPath;
    std::string kernelPath;
    std::string dtrePath;
    std::string trstPath;
    std::string rsepPath;
    
    tihmstar::Mem ibssData;
    tihmstar::Mem ibecData;
    tihmstar::Mem kernelData;
    tihmstar::Mem dtreData;
    tihmstar::Mem trstData;
    tihmstar::Mem rsepData;
    tihmstar::Mem rdskData;

    uint32_t cpid = 0;
    bool isIMG4 = idev.supportsIMG4();
    bool isRestorePlist = false;
    
    img4tool::ASN1DERElement piBSS;
    img4tool::ASN1DERElement piBEC;
    
    img4tool::ASN1DERElement pkernel;
    img4tool::ASN1DERElement pdtre;
    img4tool::ASN1DERElement ptrst;
    img4tool::ASN1DERElement prsep;

    img4tool::ASN1DERElement pim4r;

    retassure(im4m.payloadSize() || !isIMG4 || cfg.isSRD, "Missing argument: APTicket is required for IMG4 sigchk bypass");

    info("Opening firmware...");
    retassure(fzinfo = fragmentzip_open(firmwareUrl.c_str()),"Failed to fragmentzip_open firmwareUrl");
    
    info("Loading BuildManifest...");
    if (cfg.isOtaFirmware) {
        retassure(!fragmentzip_download_to_memory(fzinfo, "AssetData/boot/BuildManifest.plist", &buildmanifestBuf, &buildmanifestBufSize, fragmentzip_callback),"Failed to load BuildManifest.plist");
    }else{
        try {
            retassure(!fragmentzip_download_to_memory(fzinfo, "BuildManifest.plist", &buildmanifestBuf, &buildmanifestBufSize, fragmentzip_callback),"Failed to load BuildManifest.plist");
        } catch (...) {
            //iOS <= 3.x doesn't have BuildManifest.plist
            retassure(!fragmentzip_download_to_memory(fzinfo, "Restore.plist", &buildmanifestBuf, &buildmanifestBufSize, fragmentzip_callback),"Failed to load Restore.plist");
            isRestorePlist = true;
        }
    }
        
    plist_from_memory(buildmanifestBuf, static_cast<uint32_t>(buildmanifestBufSize), &buildmanifest, NULL);
    retassure(buildmanifest, "Failed to parse BuildManifest");
    
    if (variant.size() == 0) {
        try {
            std::string lvariant = cfg.isSRD ? RESTORE_VARIANT_RESEARCH_ERASE_INSTALL : RESTORE_VARIANT_ERASE_INSTALL;
            if ((buildidentity = tsschecker::TssRequest::getBuildIdentityForDevice(buildmanifest, idev.getDeviceCPID(), idev.getDeviceBDID(), lvariant))){
                variant = lvariant;
                debug("Implicitly setting variant to '%s'",variant.c_str());
            }
        } catch (...) {
            if (cfg.isSRD) variant = "Research";
        }
    }
    if (isRestorePlist){
        buildidentity = tsschecker::buildIdentityFromRestorePlist(buildmanifest);
    }
    if (idev.getDeviceMode() == iOSDevice::wtf){
        //boot WTF image
        char *wtfBuf = NULL;
        cleanup([&]{
            safeFree(wtfBuf);
        });
        size_t wtfBufSize = 0;
        retassure(!fragmentzip_download_to_memory(fzinfo, "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu", &wtfBuf, &wtfBufSize, fragmentzip_callback),"Failed to load WTF image");
        tihmstar::Mem wtfpayload;
        {
#ifdef HAVE_IMG1TOOL
            //patch WTF image
            wtfpayload = img1tool::getPayloadFromIMG1(wtfBuf, wtfBufSize);
            
            info("Patching WTF...");
            int patchret = 0;
            for (int i=0; i<2; i++){
                bootconfig wtf_bootcfg = bootcfg;
                launchConfig wtf_launchcfg = *bootcfg.launchcfg;
                wtf_bootcfg.curPatchComponent = '.ftw'; //wtf. (not actually a thing)
                if (i == 0){
                    //first try, iOS 3 patch
                    std::string new_s  = "SIGP:[WTF]";
                    new_s.push_back('\0');
                    std::string orig_s = "IBFL:%02X";
                    orig_s.push_back('\0');
                    orig_s.push_back('\0');
                    wtf_launchcfg.replacePatches['.ftw'].push_back({orig_s,new_s});
                } else if (i == 1){
                    //second try, iOS 2 patch
                    std::string new_s  = "] SIGP:[WTF]";
                    new_s.push_back('\0');
                    std::string orig_s = "]S5L8900 S";
                    for (int i=0; i<3; i++) {
                        orig_s.insert(orig_s.begin()+1, '\0');
                    }
                    wtf_launchcfg.replacePatches['.ftw'].push_back({orig_s,new_s});
                }else{
                    reterror("Unexpected try %d",i);
                }
                wtf_bootcfg.launchcfg = &wtf_launchcfg;
                try {
                    patchret = iBootPatchFunc((char*)wtfpayload.data(), wtfpayload.size(), (void*)&wtf_bootcfg);
                } catch (tihmstar::exception &e) {
                    continue;
                }
                if (!patchret) break;
            }
            retassure(!patchret, "Failed to patch WTF");
            wtfpayload = img1tool::createIMG1FromPayloadWithPwnage2(wtfpayload);
#else
            info("Not patching WTF. SIGNATURE CHECKS ARE STILL IN PLACE!!!");
            wtfpayload = {wtfBuf,wtfBuf+wtfBufSize};
#endif
        }
        info("Sending WTF...");
        idev.setCheckpoint();
        idev.sendComponent(wtfpayload.data(), wtfpayload.size());
        idev.waitForReconnect(20000);
    }
    
    if (bootcfg.launchcfg->justDFU && idev.getDeviceMode() == iOSDevice::dfu) {
        info("Device reached DFU mode, done!");
        return bootcfg.appliedPatches;
    }
    
    if (!buildidentity) buildidentity = tsschecker::TssRequest::getBuildIdentityForDevice(buildmanifest, idev.getDeviceCPID(), idev.getDeviceBDID(), variant);
    retassure(buildidentity, "Failed to find buildidentity for variant '%s'",variant.c_str());
    {
        plist_t p_ApChipID = NULL;
        const char *ApChipID_str = NULL;
        uint64_t ApChipID_str_len = 0;
        retassure(p_ApChipID = plist_dict_get_item(buildidentity, "ApChipID"), "Failed to get ApChipID from BuildIdentity");
        retassure(plist_get_node_type(p_ApChipID) == PLIST_STRING, "ApChipID is not of type PLIST_STRING");
        retassure(ApChipID_str = plist_get_string_ptr(p_ApChipID, &ApChipID_str_len),"Failed to get ApChipID str ptr");
        sscanf(ApChipID_str, "0x%x",&cpid);
        retassure(cpid,"Failed to parse cpid");
        info("Got CPID=0x%llx",cpid);
    }
    
    retassure(pBuildnum = plist_dict_get_item(buildmanifest, "ProductBuildVersion"), "Failed to get buildnum from BuildManifest");
    retassure(plist_get_node_type(pBuildnum) == PLIST_STRING, "ProductBuildVersion is not a string");
    plist_get_string_val(pBuildnum, &buildnum);
    retassure(buildnum, "failed to get buildnum");
    
    {
        plist_t pBuildVers = NULL;
        retassure(pBuildVers = plist_dict_get_item(buildmanifest, "ProductVersion"), "Failed to get buildnum from ProductVersion");
        retassure(plist_get_node_type(pBuildVers) == PLIST_STRING, "ProductVersion is not a string");
        {
            uint64_t len = 0;
            buildMajorVersion = atoi(plist_get_string_ptr(pBuildVers, &len));
        }
        retassure(buildMajorVersion, "failed to get buildvers");
    }
    
#pragma mark get path for components
    ibssPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "iBSS");
    info("Found iBSS at %s",ibssPath.c_str());

    if (cfg.boot_iboot_instead_of_ibec) {
        info("Booting iBoot instead of iBEC!!");
        ibecPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "iBoot");
    }else{
        ibecPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "iBEC");
    }
    info("Found iBEC at %s",ibecPath.c_str());

    if (!bootcfg.launchcfg->justiBoot || bootcfg.launchcfg->kernel_nopatch) {
        kernelPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "KernelCache");
        info("Found kernel at %s",kernelPath.c_str());

        if (cfg.isSRD || cfg.restoreBoot) {
            dtrePath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "RestoreDeviceTree");
        }else{
            dtrePath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "DeviceTree");
        }
        info("Found DeviceTree at %s",dtrePath.c_str());

        try {
            if (cfg.isSRD || cfg.restoreBoot) {
                trstPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "RestoreTrustCache");
            }else{
                trstPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "StaticTrustCache");
            }
            info("Found StaticTrustCache at %s",trstPath.c_str());
        } catch (tihmstar::TSSException_missingValue &e) {
            //
        }
        
        if (!bootcfg.launchcfg->boot_no_sep) {
            try {
                rsepPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "RestoreSEP");
                info("Found RestoreSEP at %s",rsepPath.c_str());
            } catch (tihmstar::TSSException_missingValue &e) {
                //
            }
        }
    }
    
#pragma mark get keys
    if (!cfg.noDecrypt && !cfg.isSRD) {
        info("Getting Firmware Keys...");
        try {
            iBSSKeys = libipatcher::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, ibssPath, cpid, cfg.customKeysZipUrl);
        } catch (tihmstar::exception &e) {
            info("libipatcher::getFirmwareKeyForPath failed with error:\n%s",e.dumpStr().c_str());
            if (idev.getDeviceCPID() != 0x8900){
                reterror("Failed to get iBSS keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
        }
        try {
            iBECKeys = libipatcher::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, ibecPath, cpid, cfg.customKeysZipUrl);
        } catch (tihmstar::exception &e) {
            info("libipatcher::getFirmwareKeyForPath failed with error:\n%s",e.dumpStr().c_str());
            if (idev.getDeviceCPID() != 0x8900){
                reterror("Failed to get iBEC keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
        }
        if (!bootcfg.launchcfg->justiBoot) {
            try {
                kernelKeys = libipatcher::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, kernelPath, cpid, cfg.customKeysZipUrl);
            } catch (tihmstar::exception &e) {
                info("libipatcher::getFirmwareKeyForPath(\"%s\") failed with error:\n%s",kernelPath.c_str(),e.dumpStr().c_str());
                reterror("Failed to get firmware keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
        }
    }
    
#pragma mark load components
    if (!cfg.iBSSIm4p.size()) ibssData = downloadComponent(fzinfo, ibssPath, cfg.isOtaFirmware);
    if (!cfg.iBECIm4p.size()) ibecData = downloadComponent(fzinfo, ibecPath, cfg.isOtaFirmware);

    if (cfg.isSRD) {
        auto ramdiskPath = tsschecker::TssRequest::getPathForComponentBuildIdentity(buildidentity, "RestoreRamDisk");
        info("Found RestoreRamdisk at %s",ramdiskPath.c_str());
        if (!cfg.ramdiskIm4p.size()) rdskData = downloadComponent(fzinfo, ramdiskPath, cfg.isOtaFirmware);
    }

    if (!cfg.kernelIm4p.size() && kernelPath.size()) kernelData = downloadComponent(fzinfo, kernelPath, cfg.isOtaFirmware);
    
    if (!bootcfg.launchcfg->justiBoot) {

        dtreData = downloadComponent(fzinfo, dtrePath, cfg.isOtaFirmware);

        if (trstPath.size() && !cfg.trustcache.size())
            trstData = downloadComponent(fzinfo, trstPath, cfg.isOtaFirmware);
        
        if (rsepPath.size() && !cfg.sepIm4p.size() && !bootcfg.launchcfg->boot_no_sep)
            rsepData = downloadComponent(fzinfo, rsepPath, cfg.isOtaFirmware);
    }

#pragma mark patch components
    if (cfg.iBSSIm4p.size()) {
        if (isIMG4) {
            piBSS = img4tool::ASN1DERElement(cfg.iBSSIm4p.data(), cfg.iBSSIm4p.size());
        }else{
            ibssData = cfg.iBSSIm4p;
        }
    }else if(cfg.iboot_nopatch || cfg.isSRD){
        if (isIMG4) {
            piBSS = {(uint8_t*)ibssData.data(), ibssData.size()};
        }else{
            ibssData = ibssData;
        }
    }else{
        info("Patching iBSS...");
        bootcfg.curPatchComponent = 'ssbi'; //ibss
        auto ppiBSS = libipatcher::patchCustom((char*)ibssData.data(), ibssData.size(), iBSSKeys, iBootPatchFunc, (void*)&bootcfg);
        cleanup([&]{
            safeFree(ppiBSS.first); //free buffer
        });
        if (isIMG4) {
            piBSS = {(const char *)ppiBSS.first,ppiBSS.second};
        }else{
            ibssData = {(const char *)ppiBSS.first,ppiBSS.second};
        }
    }
    
    if (bootcfg.didProcessKernelLoader) {
        info("iBSS can already load kernel, skipping iBEC...");
        bootcfg.skipiBEC = true;
    }else{
        if (cfg.iBECIm4p.size()) {
            if (isIMG4) {
                piBEC = img4tool::ASN1DERElement(cfg.iBECIm4p.data(), cfg.iBECIm4p.size());
            }else{
                ibecData = cfg.iBECIm4p;
            }
        }else if(cfg.iboot_nopatch || cfg.isSRD){
            if (isIMG4) {
                piBEC = {(uint8_t*)ibecData.data(), ibecData.size()};
            }else{
                ibecData = ibecData;
            }
        }else{
            info("Patching iBEC...");
            bootcfg.curPatchComponent = 'cebi'; //ibec
            auto ppiBEC = libipatcher::patchCustom((char*)ibecData.data(), ibecData.size(), iBECKeys, iBootPatchFunc, (void*)&bootcfg);
            cleanup([&]{
                safeFree(ppiBEC.first); //free buffer
            });
            if (isIMG4) {
                piBEC = {ppiBEC.first,ppiBEC.second};
            }else{
                ibecData = {(const char *)ppiBEC.first,ppiBEC.second};
            }
        }
    }

    if (!bootcfg.launchcfg->justiBoot) {
        if (cfg.kernelIm4p.size()) {
            if (isIMG4) {
                try {
                    pkernel = img4tool::ASN1DERElement((char*)cfg.kernelIm4p.data(), cfg.kernelIm4p.size());
                    pkernel = img4tool::renameIM4P(pkernel, "rkrn");
                } catch (tihmstar::exception &e) {
                    error("Failed to load kernel with error=%d (%s). Maybe not an IM4P file?",e.code(),e.what());
#ifdef DEBUG
                    e.dump();
#endif
                    pkernel = img4tool::getEmptyIM4PContainer("rkrn", "Kernel packed by ra1nsn0w on the fly");
                    pkernel = appendPayloadToIM4P(pkernel, (char*)cfg.kernelIm4p.data(), cfg.kernelIm4p.size());
                }
            }else{
                kernelData = cfg.kernelIm4p;
            }
        }else{
            if (cfg.kernel_nopatch){
                warning("Kernelpatches disabled by commandline argument, not modifying IM4P content");
                if (isIMG4) {
                    pkernel = {kernelData.data(),kernelData.size()};
                }
            }else{
                info("Patching kernel...\n");
                bootcfg.curPatchComponent = 'nrkr'; //rkrn (restore kernel)
                auto ppKernel = libipatcher::patchCustom((char*)kernelData.data(), kernelData.size(), kernelKeys, [&cfg,&bootcfg](char *file, size_t size, void *param)->int{
                    std::vector<patchfinder::patch> patches;
                    patchfinder::kernelpatchfinder *kpf = nullptr;
                    cleanup([&]{
                        safeDelete(kpf);
                    });

                    if (cfg.is32Bit) {
                        kpf = patchfinder::kernelpatchfinder32::make_kernelpatchfinder32(file,size);
                    }else{
                        kpf = patchfinder::kernelpatchfinder64::make_kernelpatchfinder64(file,size);
                    }
                    
                    if (cfg.doJailbreakPatches){
                        info("Kernel: Adding generic kernel patches...");
                        auto patch = kpf->get_generic_kernelpatches();
                        patches.insert(patches.end(), patch.begin(), patch.end());
                    }else{
                        
                        addKernelpatch(kpatch_codesig, get_codesignature_patches, "codesignature")
                        addKernelpatch(kpatch_mount, get_mount_patch, "mount")

                        addKernelpatch(kpatch_nuke_sandbox, get_nuke_sandbox_patch, "nuke-sandbox") else addKernelpatch(kpatch_sandbox, get_sandbox_patch, "sandbox")
                        
                        addKernelpatch(kpatch_i_can_has_debugger, get_i_can_has_debugger_patch, "get_i_can_has_debugger_patch")
                        addKernelpatch(kpatch_force_nand_writeable, get_force_NAND_writeable_patch, "get_force_NAND_writeable_patch")
                        addKernelpatch(kpatch_always_get_task_allow, get_always_get_task_allow_patch, "always_get_task_allow")
                        addKernelpatch(kpatch_allow_uid, get_allow_UID_key_patch, "get_allow_UID_key_patch");
                        addKernelpatch(kpatch_add_read_bpr, get_read_bpr_patch, "get_read_bpr_patch");
                        addKernelpatch(kpatch_no_ramdisk_detect, get_ramdisk_detection_patch, "get_ramdisk_detection_patch");
                        addKernelpatch(kpatch_noemf, get_noemf_patch, "get_noemf_patch");
                        addKernelpatch(kpatch_get_kernelbase_syscall, get_kernelbase_syscall_patch, "get_kernelbase_syscall_patch");
                        addKernelpatch(kpatch_tfp0, get_tfp0_patch, "get_tfp0_patch");
                        addKernelpatch(kpatch_tfp_unrestrict, get_tfp_anyone_allow_patch, "get_tfp_anyone_allow_patch");
                        addKernelpatch(kpatch_setuid, get_insert_setuid_patch, "get_insert_setuid_patch");
                        addKernelpatch(kpatch_force_boot_ramdisk, get_force_boot_ramdisk_patch, "get_force_boot_ramdisk_patch");
                        addKernelpatch(kpatch_root_from_sealed_apfs, get_apfs_root_from_sealed_livefs_patch, "get_apfs_root_from_sealed_livefs_patch");
                        addKernelpatch(kpatch_apfs_skip_authenticated_root, get_apfs_skip_authenticate_root_hash_patch, "get_apfs_skip_authenticate_root_hash_patch");
                    }
                    
                    if (cfg.kernelHardcodeBootargs.size()) {
                        info("Kernel: Adding hardcode boot-arg patch (%s) ...",cfg.kernelHardcodeBootargs.c_str());
                        auto patch = kpf->get_harcode_bootargs_patch(cfg.kernelHardcodeBootargs.c_str());
                        patches.insert(patches.end(), patch.begin(), patch.end());
                    }

                    if (cfg.kernelHardcoderoot_ticket_hash.size()) {
                        std::string pretty;
                        for (int i=0; i<cfg.kernelHardcoderoot_ticket_hash.size(); i++) {
                            char buf[0x10] = {};
                            snprintf(buf, sizeof(buf), "%02x",cfg.kernelHardcoderoot_ticket_hash.data()[i]);
                            pretty += buf;
                        }
                        info("Kernel: Adding hardcode boot-manifest patch (%s) ...",pretty.c_str());
                        auto patch = kpf->get_harcode_boot_manifest_patch(cfg.kernelHardcoderoot_ticket_hash.data(),cfg.kernelHardcoderoot_ticket_hash.size());
                        patches.insert(patches.end(), patch.begin(), patch.end());
                    }

                    if (cfg.replacePatches.find('nrkr') != cfg.replacePatches.end()) {
                        auto replacePatches = cfg.replacePatches.at('nrkr');
                        for (auto &r : replacePatches) {
                            auto patch = kpf->get_replace_string_patch(r.first, r.second);
                            patches.insert(patches.end(), patch.begin(), patch.end());
                        }
                        info("Inserted replacepatches for rkrn!");
                    }
                    
                    if (cfg.replacePatches.find('nrek') != cfg.replacePatches.end()) {
                        auto replacePatches = cfg.replacePatches.at('nrek');
                        for (auto &r : replacePatches) {
                            auto patch = kpf->get_replace_string_patch(r.first, r.second);
                            patches.insert(patches.end(), patch.begin(), patch.end());
                        }
                        info("Inserted replacepatches for kern!");
                    }
                    try {
                        auto userpatches = cfg.userPatches.at('nrkr'); //check if we have custom user patches for this component
                        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
                        info("Kernel: Inserted custom userpatches for rkrn!");
                    } catch (...) {
                        //
                    }
                    try {
                        auto userpatches = cfg.userPatches.at('nrek'); //check if we have custom user patches for this component
                        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
                        info("Kernel: Inserted custom userpatches for kern!");
                    } catch (...) {
                        //
                    }

                    for (auto p : cfg.activePlugins) {
                        auto ppatches = p.second->patcher('rkrn', file, size);
                        patches.insert(patches.end(), ppatches.begin(), ppatches.end());
                    }
                    
                    /* ---------- Applying collected patches ---------- */
                    info("Kernel: Applying patches...");
                    bootcfg.appliedPatches[bootcfg.curPatchComponent] = patches;
                    for (auto p : patches) {
                        uint64_t off = (uint64_t)((const char *)kpf->memoryForLoc(p._location) - file);
#ifdef DEBUG
                        printf("kernel: Applying patch=%p : ",(void*)p._location);
                        for (int i=0; i<p.getPatchSize(); i++) {
                            printf("%02x",((uint8_t*)p.getPatch())[i]);
                        }
                        printf("\n");
#endif
                        memcpy(&file[off], p.getPatch(), p.getPatchSize());
                    }
                    
                    info("Kernel: Patches applied!");
                    return 0;
                }, NULL);
                cleanup([&]{
                    safeFree(ppKernel.first); //free buffer
                });

                if (isIMG4) {
                    pkernel = {ppKernel.first,ppKernel.second};
                }else{
                    kernelData = {(const void*)ppKernel.first,ppKernel.second};
                }
            }
            if (isIMG4) {
                pkernel = img4tool::renameIM4P(pkernel, "rkrn");
            }
        }
        
        if (cfg.decrypt_devicetree) {
            info("Decrypting Devicetree");
            libipatcher::fw_key devicetreeKeys = {};
            try {
                devicetreeKeys = libipatcher::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, dtrePath, cpid, cfg.customKeysZipUrl);
            } catch (tihmstar::exception &e) {
                info("libipatcher::getFirmwareKey(\"DeviceTree\") failed with error:\n%s",e.dumpStr().c_str());
                reterror("Failed to get firmware keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
            
            //run with empty patcher function just for decryption
            auto ppdtre = libipatcher::patchCustom((char*)dtreData.data(), dtreData.size(), devicetreeKeys, [](char*, size_t, void*)->int{return 0;}, NULL);
            try {
                pdtre = {ppdtre.first,ppdtre.second, true}; //transfer ownership of buffer to ASN1DERElement
                ppdtre = {};//if transfer succeeds, discard second copy of buffer
            } catch (tihmstar::exception &e) {
                safeFree(ppdtre.first); //if transfer fails, free buffer
                throw;
            }
        }else{
            if (isIMG4) {
                pdtre = {dtreData.data(),dtreData.size()};
            }
        }
        
        if (isIMG4) {
            info("Renaming DeviceTree...\n");
            pdtre = img4tool::renameIM4P(pdtre, "rdtr");
        }
        
        if (cfg.trustcache.size()) {
            ptrst = img4tool::ASN1DERElement(cfg.trustcache.data(), cfg.trustcache.size());
            info("Renaming StaticTrustCache...\n");
            ptrst = img4tool::renameIM4P(ptrst, "rtsc");//we still want to do the renaming
        }else if (trstData.size()) {
            ptrst = {trstData.data(),trstData.size()};
            info("Renaming StaticTrustCache...\n");
            ptrst = img4tool::renameIM4P(ptrst, "rtsc");//we still want to do the renaming
        }
        
        if (!bootcfg.launchcfg->boot_no_sep) {
            if (cfg.sepIm4p.size()) {
                prsep = img4tool::ASN1DERElement(cfg.sepIm4p.data(), cfg.sepIm4p.size());
            }else if (rsepData.size()) {
                info("Renaming RestoreSEP...");
                prsep = {rsepData.data(),rsepData.size()};
                if (cfg.iboot_sep_force_local) {
                    prsep = img4tool::renameIM4P(prsep, "sepi");
                }else{
                    prsep = img4tool::renameIM4P(prsep, "rsep");
                }
            }
        }
    }else{
        if (cfg.kernel_nopatch){
            warning("Kernelpatches disabled by commandline argument, not modifying IM4P content");
            if (isIMG4) {
                pkernel = {kernelData.data(),kernelData.size()};
                pkernel = img4tool::renameIM4P(pkernel, "rkrn");
            }
        }
    }
    
#pragma mark SRD
    if (cfg.isSRD) {
        info("Requesting APTicket for SRD...");
        plist_t pRestoreKernel = NULL;
        retassure(pRestoreKernel = tsschecker::TssRequest::getElementForComponentBuildIdentity(buildidentity, "RestoreKernelCache"), "Failed to get Component RestoreKernelCache");
        {
            tihmstar::Mem sha384Hash;
#ifdef HAVE_OPENSSL
            sha384Hash.resize(SHA384_DIGEST_LENGTH);
            SHA384((uint8_t*)pkernel.buf(), pkernel.size(), sha384Hash.data());
#else
            reterror("Compiled without openssl");
#endif
            plist_dict_set_item(pRestoreKernel, "Digest", plist_new_data((char*)sha384Hash.data(), sha384Hash.size()));
            
            tsschecker::TssRequest req(buildidentity,"",true);
            req.setEcid(idev.getDeviceECID());
            req.setDeviceVals(idev.getDeviceCPID(), idev.getDeviceBDID());
            req.addDefaultAPTagsToRequest();
            req.addAllAPComponentsToRequest();
            req.setAPNonce(idev.getAPNonce());
            req.setSEPNonce(idev.getSEPNonce());
            
            std::map<std::string,tihmstar::Mem> tbm;
            {
                plist_t ticket = NULL;
                cleanup([&]{
                    safeFreeCustom(ticket, plist_free);
                });
                retassure(ticket = req.getTSSResponce(), "Failed to get APTicker");
                auto im4mdata = tsschecker::TssRequest::getApImg4TicketFromTssResponse(ticket);
                im4m = {im4mdata.data(),im4mdata.size()};
                
                if (plist_t p_tbm = plist_dict_get_item(ticket, "iBSS-TBM")) {
                    tihmstar::Mem tbm_ucon = tsschecker::TssRequest::getElementFromTssResponse(p_tbm, "ucon");
                    tihmstar::Mem tbm_ucer = tsschecker::TssRequest::getElementFromTssResponse(p_tbm, "ucer");
                    tbm["ucon"] = std::move(tbm_ucon);
                    tbm["ucer"] = std::move(tbm_ucer);
                }
            }
            
            if (tbm.size()) {
                pim4r = tihmstar::img4tool::getIM4RWithElements(tbm);
            }
        }
    }
    
    if (cfg.iboot_send_signed_sep.size()) {
        info("Requesting fresh RestoreSEP ticket");
        tsschecker::TssRequest req(buildidentity,"",true);
        req.setEcid(idev.getDeviceECID());
        req.setDeviceVals(idev.getDeviceCPID(), idev.getDeviceBDID());
        req.addDefaultAPTagsToRequest();
        req.addAllAPComponentsToRequest();
        req.setAPNonce(idev.getAPNonce());
        req.setSEPNonce(idev.getSEPNonce());

        {
            plist_t ticket = NULL;
            cleanup([&]{
                safeFreeCustom(ticket, plist_free);
            });
            retassure(ticket = req.getTSSResponce(), "Failed to get APTicker");
            auto im4mdata = tsschecker::TssRequest::getApImg4TicketFromTssResponse(ticket);
            img4tool::ASN1DERElement im4m = {im4mdata.data(),im4mdata.size()};
            info("Signing restoreSEP with fresh ticket");
            if (img4tool::isIMG4(prsep)) {
                prsep = img4tool::getIM4PFromIMG4(prsep);
            }
            prsep = img4tool::renameIM4P(prsep, "rsep");
            prsep = img4FromIM4PandIM4M(prsep,im4m);
            if (cfg.iboot_send_signed_sep.front() != '\0') {
                FILE *f = NULL;
                cleanup([&]{
                    safeFreeCustom(f, fclose);
                });
                info("Writing signed RestoreSEP to file '%s'",cfg.iboot_send_signed_sep.c_str());
                retassure(f = fopen(cfg.iboot_send_signed_sep.c_str(), "w"), "Failed to open file '%s'",cfg.iboot_send_signed_sep.c_str());
                fwrite(prsep.buf(), 1, prsep.size(), f);
            }
        }
    }

    
#pragma mark stich APTicket and send
    if (idev.getDeviceMode() != iOSDevice::recovery) {
        //are we in pwn recovery already??
        info("Sending iBSS...");
        if (isIMG4) {
            auto siBSS = img4FromIM4PandIM4M(piBSS,im4m);
            if (pim4r.size() > 2){
                siBSS = tihmstar::img4tool::appendIM4RToIMG4(siBSS, pim4r);
            }
            idev.setCheckpoint();
            idev.sendComponent(siBSS.buf(), siBSS.size());
        }else{
            idev.setCheckpoint();
            idev.sendComponent(ibssData.data(), ibssData.size());
        }
        try {
            idev.waitForReconnect(20000);
        } catch (...) {
            printf("********************** Attention! **********************\n"
                   "*   Timeout reached waiting for device entering iBSS   *\n"
                   "*         This could be caused by some USB bug         *\n"
                   "*  In this case you need to disconnect and re-connect  *\n"
                   "*     the cable (or adapter)  AT THE COMPUTER END!     *\n"
                   "*     Disconnecting at the phone end will NOT work     *\n"
                   "********************************************************\n"
                   );
            for (int i=40; i>=0; i-=10) {
                printf("Waiting %2d more seconds...\n",i);
                try {
                    idev.waitForReconnect(10000);
                    goto got_device_in_ibss;
                } catch (...) {
                    //
                }
            }
            throw;
        }
    got_device_in_ibss:;
    }else if (bootcfg.skipiBEC){
        if (isIMG4) {
            /*
             we are already in (pwn???) recovery, but this device has only 1 stage bootloader
             in order to reboot to iBSS we actually need to rename the image to iBEC
             */
            info("Renaming iBSS to iBEC...");
            piBEC = img4tool::renameIM4P(piBSS, "ibec");
            auto siBEC = img4FromIM4PandIM4M(piBEC,im4m);
            idev.setCheckpoint();
            idev.sendComponent(siBEC.buf(), siBEC.size());
            if (idev.getDeviceMode() == iOSDevice::recovery) {
                idev.sendCommand("go");
            }
            idev.waitForReconnect(30000);
        }else{
            idev.setCheckpoint();
            idev.sendComponent(ibssData.data(), ibssData.size());
            if (idev.getDeviceMode() == iOSDevice::recovery) {
                idev.sendCommand("go");
            }
            idev.waitForReconnect(30000);
        }
    }
    
    if (idev.getDeviceMode() == iOSDevice::recovery) {
        bootcfg.skipiBEC = true;
    }
    
    if (!bootcfg.skipiBEC) {
        info("Sending iBEC...");
        if (isIMG4) {
            auto siBEC = img4FromIM4PandIM4M(piBEC,im4m);
            idev.setCheckpoint();
            idev.sendComponent(siBEC.buf(), siBEC.size());
        }else{
            if (cfg.boot_iboot_instead_of_ibec) {
                info("Renaming ibot to ibec");
                auto ibec_new = img3tool::renameIMG3(ibecData.data(), ibecData.size(), "ibec");
                idev.setCheckpoint();
                idev.sendComponent(ibec_new.data(),ibec_new.size());
            }else{
                idev.setCheckpoint();
                idev.sendComponent(ibecData.data(),ibecData.size());
            }
        }
        
        if (idev.getDeviceMode() == iOSDevice::recovery) {
            idev.sendCommand("go");
        }
        idev.waitForReconnect(30000);
    }
    
    retassure(idev.getDeviceMode() == iOSDevice::recovery, "Device failed to boot iBoot");

    if (bootcfg.launchcfg->justiBoot) {
        info("iBoot reached, returning.");
        return bootcfg.appliedPatches;
    }
    
    if (cfg.sendAllComponents) {
        plist_array_iter m_iter = NULL;
        char *key_component = NULL;
        cleanup([&]{
            safeFree(key_component);
            safeFree(m_iter);
        });
        plist_t manifest = NULL;
        plist_t p_component_val = NULL;

        manifest = plist_dict_get_item(buildidentity, "Manifest");
        plist_dict_new_iter(manifest, &m_iter);
        for (plist_dict_next_item(manifest, m_iter, &key_component, &p_component_val); p_component_val; safeFree(key_component),plist_dict_next_item(manifest, m_iter, &key_component, &p_component_val)) {
            
            if (strcmp(key_component, "AppleLogo") == 0
                || strcmp(key_component, "BatteryCharging0") == 0
                || strcmp(key_component, "BatteryCharging1") == 0
                || strcmp(key_component, "BatteryFull") == 0
                || strcmp(key_component, "BatteryLow0") == 0
                || strcmp(key_component, "BatteryLow1") == 0
                || strcmp(key_component, "BatteryPlugin") == 0
                || strcmp(key_component, "DeviceTree") == 0
                || strcmp(key_component, "KernelCache") == 0
                || strcmp(key_component, "LLB") == 0
                || strcmp(key_component, "RestoreDeviceTree") == 0
                || strcmp(key_component, "RestoreKernelCache") == 0
                || strcmp(key_component, "RestoreLogo") == 0
                || strcmp(key_component, "RestoreRamDisk") == 0
                || strcmp(key_component, "RestoreSEP") == 0
                || strcmp(key_component, "RestoreTrustCache") == 0
                || strcmp(key_component, "SEP") == 0
                || strcmp(key_component, "StaticTrustCache") == 0
                || strcmp(key_component, "iBEC") == 0
                || strcmp(key_component, "iBSS") == 0
                || strcmp(key_component, "iBoot") == 0
                || strcmp(key_component, "RestoreTrustCache") == 0
                || strcmp(key_component, "SEP") == 0) continue;
            
            img4tool::ASN1DERElement im4p;
            auto customComponent = cfg.customComponents.find(key_component);
            if (customComponent == cfg.customComponents.end()) {
                plist_t info = plist_dict_get_item(p_component_val, "Info");
                assure(info);
                plist_t p_IsLoadedByiBoot = plist_dict_get_item(info, "IsLoadedByiBoot");
                if (!p_IsLoadedByiBoot || !plist_bool_val_is_true(p_IsLoadedByiBoot)) continue;
                plist_t path = plist_dict_get_item(info, "Path");
                
                plist_t p_Img4PayloadType = plist_dict_get_item(info, "Img4PayloadType");
                retassure(isIMG4, "expecting IMG4 here");
                {
                    char *path_str = NULL;
                    char *im4pTagName = NULL;
                    cleanup([&]{
                        safeFree(im4pTagName);
                        safeFree(path_str);
                    });
                    plist_get_string_val(path, &path_str);
                    
                    auto cmpnt = downloadComponent(fzinfo, path_str, cfg.isOtaFirmware);
                    
                    if (p_Img4PayloadType) {
                        plist_get_string_val(p_Img4PayloadType, &im4pTagName);
                    }
                    
                    im4p = {cmpnt.data(),cmpnt.size()};
                    if (im4pTagName) {
                        info("Renaming (%s) to '%s'",key_component,im4pTagName);
                        im4p = img4tool::renameIM4P(im4p, im4pTagName);
                    }
                }
            }else{
                info("Sending custom component '%s'",key_component);
                im4p = {customComponent->second.data(),customComponent->second.size()};
            }
            
            auto img4 = img4FromIM4PandIM4M(im4p,im4m);
            idev.sendComponent(img4.buf(), img4.size());
            idev.sendCommand("firmware");
        }
    }

    
    if (!cfg.bootlogoIm4p.size()){
        idev.sendCommand("bgcolor 0 0 255");
    }else{
        info("Sending Custom logo...");
        if (isIMG4){
            img4tool::ASN1DERElement plogo(cfg.bootlogoIm4p.data(), cfg.bootlogoIm4p.size());
            auto slogo = img4FromIM4PandIM4M(plogo,im4m);
            idev.sendComponent(slogo.buf(), slogo.size());
        }else{
            idev.sendComponent(cfg.bootlogoIm4p.data(), cfg.bootlogoIm4p.size());
        }
        idev.sendCommand("setpicture 0");
        idev.sendCommand("bgcolor 0 0 0");
    }
    
    if (cfg.setAutobootFalse) {
        info("Disabling auto-boot");
        idev.sendCommand("setenv auto-boot false");
        idev.sendCommand("saveenv");
    }
    
    if (ptrst.payloadSize()) {
        info("Sending StaticTrustCache...");
        auto strst = img4FromIM4PandIM4M(ptrst,im4m);
        idev.sendComponent(strst.buf(), strst.size());
        idev.sendCommand("firmware");
    }
    
    if (prsep.payloadSize()) {
        info("Sending RestoreSEP...");
        img4tool::ASN1DERElement srsep;
        if (img4tool::isIMG4(prsep)) {
            info("SEP is already IMG4 file, not re-signing with the supplied APTicket!");
            srsep = prsep;
        }else{
            srsep = img4FromIM4PandIM4M(prsep,im4m);
        }

        idev.sendComponent(srsep.buf(), srsep.size());
        idev.sendCommand("rsepfirmware");
    }
    
    info("Sending DeviceTree...");
    if (isIMG4) {
        auto sdtre = img4FromIM4PandIM4M(pdtre,im4m);
        idev.sendComponent(sdtre.buf(), sdtre.size());
    }else{
        idev.sendComponent(dtreData.data(), dtreData.size());
    }
    idev.sendCommand("devicetree");

    if (cfg.ramdiskIm4p.size() || rdskData.size()) {
        const tihmstar::Mem *realRDSK = cfg.ramdiskIm4p.size() ? &cfg.ramdiskIm4p : &rdskData;
        if (isIMG4) {
            img4tool::ASN1DERElement sramdisk;
            bool ramdiskNeedsPacking = cfg.ramdiskIsRawDMG;

            if (!ramdiskNeedsPacking) {
                try {
                    img4tool::ASN1DERElement pramdisk = img4tool::ASN1DERElement((*realRDSK).data(), (*realRDSK).size());
                    sramdisk = img4FromIM4PandIM4M(pramdisk,im4m);
                } catch (tihmstar::exception &e) {
                    error("Failed to load ramdisk with error=%d (%s). Maybe not an IM4P file?",e.code(),e.what());
#ifdef DEBUG
                    e.dump();
#endif
                    ramdiskNeedsPacking = true;
                }
            }
            
            if (ramdiskNeedsPacking){
                info("Packing raw ramdisk to IM4P...");
                img4tool::ASN1DERElement pramdisk = img4tool::getEmptyIM4PContainer("rdsk", "Ramdisk packed by ra1nsn0w on the fly");
                pramdisk = appendPayloadToIM4P(pramdisk, (*realRDSK).data(), (*realRDSK).size());
                sramdisk = img4FromIM4PandIM4M(pramdisk, im4m);
            }
            
            info("Sending ramdisk...");
            idev.sendComponent(sramdisk.buf(), sramdisk.size());
        }else{
            bool ramdiskNeedsPacking = cfg.ramdiskIsRawDMG;
            tihmstar::Mem tmpbuf;
            const uint8_t *ramdiskBufPtr = NULL;
            size_t ramdiskBufSize = 0;

            if (!ramdiskNeedsPacking){
                try {
                    uint32_t type = img3tool::getImg3ImageType((*realRDSK).data(), (*realRDSK).size());
                    retassure(type == 'rdsk', "TYPE not 'rdsk', this is bad!");
                    ramdiskBufPtr = (*realRDSK).data();
                    ramdiskBufSize = (*realRDSK).size();
                } catch (tihmstar::exception &e) {
                    error("Failed to load get ramdisk type with error=%d (%s). Maybe not an IMG3 file?",e.code(),e.what());
#ifdef DEBUG
                    e.dump();
#endif
                    ramdiskNeedsPacking = true;
                }
            }

            if (ramdiskNeedsPacking){
                info("Packing raw ramdisk to IMG3...");
                tmpbuf = img3tool::appendPayloadToIMG3(img3tool::getEmptyIMG3Container('rdsk'), 'DATA', (*realRDSK));
                ramdiskBufPtr = tmpbuf.data();
                ramdiskBufSize = tmpbuf.size();
            }
            
            info("Sending ramdisk...");
            idev.sendComponent(ramdiskBufPtr, ramdiskBufSize);
        }
        idev.sendCommand("ramdisk");
    } else if (!isIMG4){
        /*
         If we're dealing with IMG3, then we always need to send a ramdisk, even if we want to do localboot.
         If the bootarg doesn't contain "rd=md0" then ramdisk is ignored by the kernel
         */
        info("Sending dummy ramdisk...");
        std::string payload = "[THIS IS A RAMDISK]";
        auto rdsk = img3tool::appendPayloadToIMG3(img3tool::getEmptyIMG3Container('rdsk'), 'DATA', payload.data(), payload.size());
        idev.sendComponent(rdsk.data(), rdsk.size());
        idev.sendCommand("ramdisk");
    }
    
    if (cfg.ra1nra1n.size()) {
        info("Sending payload...");

        std::string loadAddr = idev.getEnv("loadaddr");
        idev.sendComponent(cfg.ra1nra1n.data(), cfg.ra1nra1n.size());

        std::string memcpyCommand;
        if (buildMajorVersion >= 13) {
            memcpyCommand = "memcpy 0x818000000 ";
        }else{
            memcpyCommand = "memcpy 0x820000000 ";
        }
        memcpyCommand += loadAddr;
        memcpyCommand += " 0x200000";

        idev.sendCommand(memcpyCommand);
    }

    info("Sending kernel...");
    if (isIMG4) {
        auto skernel = img4FromIM4PandIM4M(pkernel,im4m);
        idev.sendComponent(skernel.buf(), skernel.size());
    }else{
        idev.sendComponent(kernelData.data(), kernelData.size());
    }
    
    if (!cfg.nobootx) {
        info("Booting...");
        idev.setCheckpoint();
        idev.sendCommand("bootx");
        idev.waitForDisconnect(10000);
    }

    info("Done!");
    return bootcfg.appliedPatches;
}
