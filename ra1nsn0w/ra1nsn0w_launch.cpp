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
#include <libfwkeyfetch/libfwkeyfetch.hpp>
#include <img3tool/img3tool.hpp>
#include <tsschecker/tsschecker.hpp>
#include <tsschecker/TssRequest.hpp>
#include <tsschecker/TSSException.hpp>
#include <plist/plist.h>

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

#pragma mark ra1nsn0w

static img4tool::ASN1DERElement img4FromIM4PandIM4M(const img4tool::ASN1DERElement &im4p, const img4tool::ASN1DERElement &im4m){
    img4tool::ASN1DERElement img4 = img4tool::getEmptyIMG4Container();
    img4 = img4tool::appendIM4PToIMG4(img4, im4p);
    img4 = img4tool::appendIM4MToIMG4(img4, im4m);
    return img4;
}

static tihmstar::Mem downloadComponent(fragmentzip_t *fzinfo, std::string path, bool isOta){
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

#pragma mark public
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
    libfwkeyfetch::fw_key iBSSKeys = {};
    libfwkeyfetch::fw_key iBECKeys = {};
    libfwkeyfetch::fw_key kernelKeys = {};
    
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
            int patchret = -1;
            for (int i=0; i<3; i++){
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
                    patchret = patchFunciBoot((char*)wtfpayload.data(), wtfpayload.size(), &wtf_bootcfg);
                } catch (tihmstar::exception &e) {
#ifdef DEBUG
                    e.dump();
#endif
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
            iBSSKeys = libfwkeyfetch::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, ibssPath, cpid, cfg.customKeysZipUrl);
        } catch (tihmstar::exception &e) {
            info("libfwkeyfetch::getFirmwareKeyForPath failed with error:\n%s",e.dumpStr().c_str());
            if (idev.getDeviceCPID() != 0x8900){
                reterror("Failed to get iBSS keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
        }
        try {
            iBECKeys = libfwkeyfetch::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, ibecPath, cpid, cfg.customKeysZipUrl);
        } catch (tihmstar::exception &e) {
            info("libfwkeyfetch::getFirmwareKeyForPath failed with error:\n%s",e.dumpStr().c_str());
            if (idev.getDeviceCPID() != 0x8900){
                reterror("Failed to get iBEC keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
        }
        if (!bootcfg.launchcfg->justiBoot) {
            try {
                kernelKeys = libfwkeyfetch::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, kernelPath, cpid, cfg.customKeysZipUrl);
            } catch (tihmstar::exception &e) {
                info("libfwkeyfetch::getFirmwareKeyForPath(\"%s\") failed with error:\n%s",kernelPath.c_str(),e.dumpStr().c_str());
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
        if (isIMG4) {
            piBSS = patchIMG4(ibssData.data(), ibssData.size(), iBSSKeys.iv, iBSSKeys.key, "iBoot", (int(*)(void*,size_t,void*))patchFunciBoot, (void*)&bootcfg);
        }else{
            ibssData = patchIMG3(ibssData.data(), ibssData.size(), iBSSKeys.iv, iBSSKeys.key, "iBoot", (int(*)(void*,size_t,void*))patchFunciBoot, (void*)&bootcfg);
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
            if (isIMG4) {
                piBEC = patchIMG4(ibecData.data(), ibecData.size(), iBECKeys.iv, iBECKeys.key, "iBoot", (int(*)(void*,size_t,void*))patchFunciBoot, (void*)&bootcfg);
            }else{
                ibecData = patchIMG3(ibecData.data(), ibecData.size(), iBECKeys.iv, iBECKeys.key, "iBoot", (int(*)(void*,size_t,void*))patchFunciBoot, (void*)&bootcfg);
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
                if (isIMG4) {
                    pkernel = patchIMG4(kernelData.data(), kernelData.size(), kernelKeys.iv, kernelKeys.key, "Darwin", (int(*)(void*,size_t,void*))patchFunciBoot, (void*)&bootcfg);
                }else{
                    kernelData = patchIMG3(kernelData.data(), kernelData.size(), kernelKeys.iv, kernelKeys.key, "Darwin", (int(*)(void*,size_t,void*))patchFunciBoot, (void*)&bootcfg);
                }
            }
            if (isIMG4) {
                pkernel = img4tool::renameIM4P(pkernel, "rkrn");
            }
        }
        
        if (cfg.decrypt_devicetree) {
            info("Decrypting Devicetree");
            libfwkeyfetch::fw_key devicetreeKeys = {};
            try {
                devicetreeKeys = libfwkeyfetch::getFirmwareKeyForPath(idev.getDeviceProductType(),buildnum, dtrePath, cpid, cfg.customKeysZipUrl);
            } catch (tihmstar::exception &e) {
                info("libfwkeyfetch::getFirmwareKey(\"DeviceTree\") failed with error:\n%s",e.dumpStr().c_str());
                reterror("Failed to get firmware keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
            }
            
            //run with empty patcher function just for decryption
            if (isIMG4) {
                pdtre = patchIMG4(dtreData.data(), dtreData.size(), devicetreeKeys.iv, devicetreeKeys.key, NULL, [](void*, size_t, void*)->int{return 0;}, NULL);
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
