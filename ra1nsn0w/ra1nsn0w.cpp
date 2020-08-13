//
//  ra1nsn0w.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "ra1nsn0w.hpp"
#include <libgeneral/macros.h>
#include <plist/plist.h>
#include <libipatcher/libipatcher.hpp>
#include <liboffsetfinder64/ibootpatchfinder64.hpp>
#include <liboffsetfinder64/kernelpatchfinder64.hpp>

extern "C"{
#include <libfragmentzip/libfragmentzip.h>
};


using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;


struct bootconfig{
    const launchConfig *launchcfg;
    bool didProcessKernelLoader;
    bool skipiBEC;
    uint32_t curPatchComponent;
};

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

plist_t getBuildidentityWithBoardconfig(plist_t buildManifest, const char *boardconfig){
    plist_t rt = NULL;
    plist_t buildidentities = plist_dict_get_item(buildManifest, "BuildIdentities");
    if (!buildidentities || plist_get_node_type(buildidentities) != PLIST_ARRAY){
        reterror("[TSSR] Error: could not get BuildIdentities\n");
    }
    for (int i=0; i<plist_array_get_size(buildidentities); i++) {
        rt = plist_array_get_item(buildidentities, i);
        if (!rt || plist_get_node_type(rt) != PLIST_DICT){
            reterror("[TSSR] Error: could not get id%d\n",i);
        }
        plist_t infodict = plist_dict_get_item(rt, "Info");
        if (!infodict || plist_get_node_type(infodict) != PLIST_DICT){
            reterror("[TSSR] Error: could not get infodict\n");
        }
        plist_t RestoreBehavior = plist_dict_get_item(infodict, "RestoreBehavior");
        if (!RestoreBehavior || plist_get_node_type(RestoreBehavior) != PLIST_STRING){
            reterror("[TSSR] Error: could not get RestoreBehavior\n");
        }
        char *string = NULL;
        plist_t DeviceClass = plist_dict_get_item(infodict, "DeviceClass");
        if (!DeviceClass || plist_get_node_type(DeviceClass) != PLIST_STRING){
            reterror("[TSSR] Error: could not get DeviceClass\n");
        }
        plist_get_string_val(DeviceClass, &string);
        if (strcasecmp(string, boardconfig) == 0)
            return rt;
    }
    reterror("Failed to find matching buildidentity");
}

int build_identity_get_component_path(plist_t build_identity, const char* component, char** path) {
    char* filename = NULL;

    plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
    if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
        error("ERROR: Unable to find manifest node\n");
        if (filename)
            free(filename);
        return -1;
    }

    plist_t component_node = plist_dict_get_item(manifest_node, component);
    if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
        error("ERROR: Unable to find component node for %s\n", component);
        if (filename)
            free(filename);
        return -1;
    }

    plist_t component_info_node = plist_dict_get_item(component_node, "Info");
    if (!component_info_node || plist_get_node_type(component_info_node) != PLIST_DICT) {
        error("ERROR: Unable to find component info node for %s\n", component);
        if (filename)
            free(filename);
        return -1;
    }

    plist_t component_info_path_node = plist_dict_get_item(component_info_node, "Path");
    if (!component_info_path_node || plist_get_node_type(component_info_path_node) != PLIST_STRING) {
        error("ERROR: Unable to find component info path node for %s\n", component);
        if (filename)
            free(filename);
        return -1;
    }
    plist_get_string_val(component_info_path_node, &filename);

    *path = filename;
    return 0;
}

#pragma mark ra1nsn0w

img4tool::ASN1DERElement img4FromIM4PandIM4M(const img4tool::ASN1DERElement &im4p, const img4tool::ASN1DERElement &im4m){
    img4tool::ASN1DERElement img4 = img4tool::getEmptyIMG4Container();
    img4 = img4tool::appendIM4PToIMG4(img4, im4p);
    img4 = img4tool::appendIM4MToIMG4(img4, im4m);
    return img4;
}


int iBootPatchFunc(char *file, size_t size, void *param){
    bootconfig *bcfg = (bootconfig *)param;
    const launchConfig *cfg = bcfg->launchcfg;
    
    std::vector<offsetfinder64::patch> patches;
    offsetfinder64::ibootpatchfinder64 *ibpf = offsetfinder64::ibootpatchfinder64::make_ibootpatchfinder64(file,size);
    cleanup([&]{
        if (ibpf){
            delete ibpf;
        }
    });
    
    {
        printf("iBoot: Adding sigcheck patch...\n");
        auto patch = ibpf->get_sigcheck_patch();
        patches.insert(patches.end(), patch.begin(), patch.end());
    }
    
    {
        printf("iBoot: Adding debug_enable patch...\n");
        auto patch = ibpf->get_debug_enabled_patch();
        patches.insert(patches.end(), patch.begin(), patch.end());
    }
    
    if (cfg->add_rw_and_rx_mappings) {
        printf("iBoot: Adding add_rw_and_rx_mappings patch...\n");
        auto patch = ibpf->get_rw_and_x_mappings_patch_el1();
        patches.insert(patches.end(), patch.begin(), patch.end());
    }
    
    
    if (ibpf->has_recovery_console()) {
        bcfg->didProcessKernelLoader = true;
        if (cfg->ra1nra1nPath){
            {
                printf("iBoot: Adding memcpy patch...\n");
                auto patch = ibpf->replace_bgcolor_with_memcpy();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }

            {
                printf("iBoot: Adding ra1nra1n patch...\n");
                auto patch = ibpf->get_ra1nra1n_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
        }else{
            {
                printf("iBoot: Adding boot-arg patch (%s) ...\n",cfg->bootargs.c_str());
                auto patch = ibpf->get_boot_arg_patch(cfg->bootargs.c_str());
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            
            if (cfg->cmdhandler.size()){
                for (auto handler : cfg->cmdhandler) {
                    printf("iBoot: Adding cmdhandler patch (%s=0x%016llx) ...\n",handler.first.c_str(),handler.second);
                    auto patch = ibpf->get_cmd_handler_patch(handler.first.c_str(),handler.second);
                    patches.insert(patches.end(), patch.begin(), patch.end());
                }
            }
            
            if (cfg->nvramUnlock) {
                printf("iBoot: Adding nvram_unlock patch...\n");
                auto patch = ibpf->get_unlock_nvram_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
        }
        
    }
    
    
    try {
        auto userpatches = cfg->userPatches.at(bcfg->curPatchComponent); //check if we have custom user patches for this component
        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
        printf("Inserted custom userpatches for current component!\n");
    } catch (...) {
        //
    }
    
    

    
    /* ---------- Applying collected patches ---------- */
    for (auto p : patches) {
        offsetfinder64::offset_t off = (offsetfinder64::offset_t)(p._location - ibpf->find_base());
        printf("iBoot: Applying patch=%p : ",(void*)p._location);
        for (int i=0; i<p._patchSize; i++) {
            printf("%02x",((uint8_t*)p._patch)[i]);
        }
        printf("\n");
        memcpy(&file[off], p._patch, p._patchSize);
    }
    printf("iBoot: Patches applied!\n");
    return 0;
}

void ra1nsn0w::launchDevice(iOSDevice &idev, std::string firmwareUrl, const img4tool::ASN1DERElement &im4m, const launchConfig &cfg){
    bootconfig bootcfg = {&cfg};
    fragmentzip_t *fzinfo = NULL;
    char *buildmanifestBuf = NULL;
    size_t buildmanifestBufSize = 0;
    plist_t buildmanifest = NULL;
    
    char *ibssPath = NULL;
    char *ibecPath = NULL;
    char *kernelPath = NULL;
    char *dtrePath = NULL;
    char *trstPath = NULL;

    char *ibssBuf = NULL;   size_t ibssBufSize = 0;
    char *ibecBuf = NULL;   size_t ibecBufSize = 0;
    char *kernelBuf = NULL; size_t kernelBufSize = 0;
    char *dtreBuf = NULL;   size_t dtreBufSize = 0;
    char *trstBuf = NULL;   size_t trstBufSize = 0;

    char *buildnum = NULL;

    cleanup([&]{
        safeFree(buildnum);

        safeFree(dtreBuf);
        safeFree(kernelBuf);
        safeFree(ibecBuf);
        safeFree(ibssBuf);
        
        safeFree(dtreBuf);
        safeFree(kernelBuf);
        safeFree(ibecPath);
        safeFree(ibssPath);

        safeFreeCustom(buildmanifest,plist_free);
        safeFree(buildmanifestBuf);
        safeFreeCustom(fzinfo,fragmentzip_close);
    });
    plist_t buildidentity = NULL;
    plist_t pBuildnum = NULL;
    libipatcher::pwnBundle bundle;
    libipatcher::fw_key kernelKeys;

    img4tool::ASN1DERElement piBSS{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    img4tool::ASN1DERElement piBEC{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};

    img4tool::ASN1DERElement pkernel{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    img4tool::ASN1DERElement pdtre{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    img4tool::ASN1DERElement ptrst{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};

    
    printf("Opening firmware...\n");
    retassure(fzinfo = fragmentzip_open(firmwareUrl.c_str()),"Failed to fragmentzip_open firmwareUrl");
    
    printf("Loading BuildManifest...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, "BuildManifest.plist", &buildmanifestBuf, &buildmanifestBufSize, fragmentzip_callback),"Failed to load BuildManifest.plist");
        
    plist_from_memory(buildmanifestBuf, static_cast<uint32_t>(buildmanifestBufSize), &buildmanifest);
    retassure(buildmanifest, "Failed to parse BuildManifest");
    
    buildidentity = getBuildidentityWithBoardconfig(buildmanifest, idev.getDeviceHardwareModel().c_str());
    
    retassure(pBuildnum = plist_dict_get_item(buildmanifest, "ProductBuildVersion"), "Failed to get buildnum from BuildManifest");
    retassure(plist_get_node_type(pBuildnum) == PLIST_STRING, "ProductBuildVersion is not a string");
    plist_get_string_val(pBuildnum, &buildnum);
    retassure(buildnum, "failed to get buildnum");
    
    printf("Getting Firmware Keys...\n");
    try {
        bundle = libipatcher::getPwnBundleForDevice(idev.getDeviceProductType(),buildnum);
    } catch (tihmstar::exception &e) {
        printf("libipatcher::getPwnBundleForDevice failed with error:\n");
        e.dump();
        reterror("Failed to get firmware keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
    }
    
    try {
        kernelKeys = libipatcher::getFirmwareKey(idev.getDeviceProductType(),buildnum, "Kernelcache");
    } catch (tihmstar::exception &e) {
        printf("libipatcher::getFirmwareKey(\"Kernelcache\") failed with error:\n");
        e.dump();
        reterror("Failed to get firmware keys. You can yout wikiproxy to get them from theiphonewiki or if keys are not available you can create your own bundle and host it on localhost:8888");
    }
    
#pragma mark get path for components
    retassure(!build_identity_get_component_path(buildidentity, "iBSS", &ibssPath), "Failed to get iBSS Path from BuildIdentity");
    printf("Found iBSS at %s\n",ibssPath);

    retassure(!build_identity_get_component_path(buildidentity, "iBEC", &ibecPath), "Failed to get iBEC Path from BuildIdentity");
    printf("Found iBEC at %s\n",ibecPath);

    retassure(!build_identity_get_component_path(buildidentity, "KernelCache", &kernelPath), "Failed to get kernel Path from BuildIdentity");
    printf("Found kernel at %s\n",kernelPath);

    retassure(!build_identity_get_component_path(buildidentity, "DeviceTree", &dtrePath), "Failed to get DeviceTree Path from BuildIdentity");
    printf("Found DeviceTree at %s\n",dtrePath);

    if (!build_identity_get_component_path(buildidentity, "StaticTrustCache", &trstPath)){
        printf("Found StaticTrustCache at %s\n",trstPath);
    }
    
#pragma mark load components
    printf("Loading iBSS...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, ibssPath, &ibssBuf, &ibssBufSize, fragmentzip_callback),"Failed to load iBSS");
    
    printf("Loading iBEC...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, ibecPath, &ibecBuf, &ibecBufSize, fragmentzip_callback),"Failed to load iBEC");

    printf("Loading kernel...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, kernelPath, &kernelBuf, &kernelBufSize, fragmentzip_callback),"Failed to load kernel");

    printf("Loading DeviceTree...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, dtrePath, &dtreBuf, &dtreBufSize, fragmentzip_callback),"Failed to load DeviceTree");

    if (trstPath) {
        printf("Loading StaticTrustCache...\n");
        retassure(!fragmentzip_download_to_memory(fzinfo, trstPath, &trstBuf, &trstBufSize, fragmentzip_callback),"Failed to load StaticTrustCache");
    }

#pragma mark patch components
    printf("Patching iBSS...\n");
    bootcfg.curPatchComponent = 'ssbi'; //ibss
    auto ppiBSS = libipatcher::patchCustom(ibssBuf, ibssBufSize, bundle.iBSSKey, iBootPatchFunc, (void*)&bootcfg);
    try {
        piBSS = {ppiBSS.first,ppiBSS.second, true}; //transfer ownership of buffer to ASN1DERElement
    } catch (tihmstar::exception &e) {
        safeFree(ppiBSS.first); //if transfer fails, free buffer
        throw;
    }
    ppiBSS = {};//if transfer succeeds, discard second copy of buffer
    
    if (bootcfg.didProcessKernelLoader) {
        printf("iBSS can already load kernel, skipping iBEC...\n");
        bootcfg.skipiBEC = true;
    }else{
        printf("Patching iBEC...\n");
        bootcfg.curPatchComponent = 'cebi'; //ibec
        auto ppiBEC = libipatcher::patchCustom(ibecBuf, ibecBufSize, bundle.iBECKey, iBootPatchFunc, (void*)&bootcfg);
        try {
            piBEC = {ppiBEC.first,ppiBEC.second, true}; //transfer ownership of buffer to ASN1DERElement
        } catch (tihmstar::exception &e) {
            safeFree(ppiBEC.first); //if transfer fails, free buffer
            throw;
        }
        ppiBEC = {};//if transfer succeeds, discard second copy of buffer
    }

    
    if (cfg.kernelIm4pPath) {
        FILE *f = NULL;
        char *kernelim4p = NULL;
        cleanup([&]{
            safeFree(kernelim4p);
            safeFreeCustom(f, fclose);
        });
        size_t kernelim4pSize = 0;
        printf("Loading kernelfile at=%s\n",cfg.kernelIm4pPath);
        
        assure(f = fopen(cfg.kernelIm4pPath, "rb"));
        fseek(f, 0, SEEK_END);
        assure(kernelim4pSize = ftell(f));
        fseek(f, 0, SEEK_SET);
        assure(kernelim4p = (char*)malloc(kernelim4pSize));
        assure(fread(kernelim4p, 1, kernelim4pSize, f) == kernelim4pSize);
        
        pkernel = img4tool::ASN1DERElement(kernelim4p, kernelim4pSize, true);
        kernelim4p = NULL;
    }else{
        printf("Patching kernel...\n");
        bootcfg.curPatchComponent = 'nrkr'; //rkrn (restore kernel)
        auto ppKernel = libipatcher::patchCustom(kernelBuf, kernelBufSize, kernelKeys, [&cfg](char *file, size_t size, void *param)->int{
            std::vector<offsetfinder64::patch> patches;
            
            offsetfinder64::kernelpatchfinder64 kpf(file,size);
            
            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding MarijuanARM patch...\n");
                auto patch = kpf.get_MarijuanARM_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            
            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding task_conversion_eval patch...\n");
                auto patch = kpf.get_task_conversion_eval_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }

            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding vm_fault_internal patch...\n");
                auto patch = kpf.get_vm_fault_internal_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            
            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding trustcache_true patch...\n");
                auto patch = kpf.get_trustcache_true_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }

            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding mount patch...\n");
                auto patch = kpf.get_mount_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }

            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding tfp0 patch...\n");
                auto patch = kpf.get_tfp0_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            
            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding amfi patch...\n");
                auto patch = kpf.get_amfi_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            
            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding get_task_allow patch...\n");
                auto patch = kpf.get_get_task_allow_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }

            if (cfg.doJailbreakPatches){
                printf("Kernel: Adding apfs_snapshot patch...\n");
                auto patch = kpf.get_apfs_snapshot_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }

            
            /* ---------- Applying collected patches ---------- */
            for (auto p : patches) {
                offsetfinder64::offset_t off = (offsetfinder64::offset_t)((const char *)kpf.memoryForLoc(p._location) - file);
                printf("kernel: Applying patch=%p : ",(void*)p._location);
                for (int i=0; i<p._patchSize; i++) {
                    printf("%02x",((uint8_t*)p._patch)[i]);
                }
                printf("\n");
                memcpy(&file[off], p._patch, p._patchSize);
            }
            printf("kernel: Patches applied!\n");
            return 0;
        }, NULL);
        try {
            pkernel = {ppKernel.first,ppKernel.second, true}; //transfer ownership of buffer to ASN1DERElement
        } catch (tihmstar::exception &e) {
            safeFree(ppKernel.first); //if transfer fails, free buffer
            throw;
        }
        ppKernel = {};//if transfer succeeds, discard second copy of buffer
        pkernel = img4tool::renameIM4P(pkernel, "rkrn");
    }
    
    printf("Patching DeviceTree...\n");
    pdtre = {dtreBuf,dtreBufSize};
    pdtre = img4tool::renameIM4P(pdtre, "rdtr");
    
    if (trstBuf && trstBufSize) {
        printf("Patching StaticTrustCache...\n");
        ptrst = {trstBuf,trstBufSize};
        ptrst = img4tool::renameIM4P(ptrst, "rtsc");
    }
    
#pragma mark stich APTicket and send
    if (idev.getDeviceMode() != iOSDevice::recovery) {
        //are we in pwn recovery already??
        printf("Sending iBSS...\n");
        auto siBSS = img4FromIM4PandIM4M(piBSS,im4m);
        idev.setCheckpoint();
        idev.sendComponent(siBSS.buf(), siBSS.size());
    }else if (bootcfg.skipiBEC){
        /*
         we are already in (pwn???) recovery, but this device has only 1 stage bootloader
         in order to reboot to iBSS we actually need to rename the image to iBEC
         */
        printf("Renaming iBSS to iBEC...\n");
        piBEC = img4tool::renameIM4P(piBSS, "ibec");
        auto siBEC = img4FromIM4PandIM4M(piBEC,im4m);
        idev.setCheckpoint();
        idev.sendComponent(siBEC.buf(), siBEC.size());
        if (idev.getDeviceMode() == iOSDevice::recovery) {
            idev.sendCommand("go");
        }
    }
    
    if (!bootcfg.skipiBEC) {
        idev.waitForReconnect(10000);
        printf("Sending iBEC...\n");
        auto siBEC = img4FromIM4PandIM4M(piBEC,im4m);
        idev.setCheckpoint();
        idev.sendComponent(siBEC.buf(), siBEC.size());
        if (idev.getDeviceMode() == iOSDevice::recovery) {
            idev.sendCommand("go");
        }
    }

    idev.waitForReconnect(50000);
    
    retassure(idev.getDeviceMode() == iOSDevice::recovery, "Device failed to boot iBoot");

    if (bootcfg.launchcfg->justiBoot) {
        printf("iBoot reached, returning.\n");
        return;
    }

    
    if (!cfg.ra1nra1nPath) {
        idev.sendCommand("bgcolor 0 0 255");
    }
    
    if (cfg.apticketdump) {
        printf("Option apticketdump detected, returning.\n");
        return;
    }
    
    if (ptrst.size()) {
        printf("Sending StaticTrustCache...\n");
        auto strst = img4FromIM4PandIM4M(ptrst,im4m);
        idev.sendComponent(strst.buf(), strst.size());
        idev.sendCommand("firmware");
    }
    
    printf("Sending DeviceTree...\n");
    auto sdtre = img4FromIM4PandIM4M(pdtre,im4m);
    idev.sendComponent(sdtre.buf(), sdtre.size());
    idev.sendCommand("devicetree");

    if (cfg.ramdiskIm4pPath) {
        FILE *f = NULL;
        char *im4p = NULL;
        cleanup([&]{
            safeFree(im4p);
            safeFreeCustom(f, fclose);
        });
        size_t im4pSize = 0;
        printf("Loading ramdisk at=%s\n",cfg.ramdiskIm4pPath);
        
        assure(f = fopen(cfg.ramdiskIm4pPath, "rb"));
        fseek(f, 0, SEEK_END);
        assure(im4pSize = ftell(f));
        fseek(f, 0, SEEK_SET);
        assure(im4p = (char*)malloc(im4pSize));
        assure(fread(im4p, 1, im4pSize, f) == im4pSize);
        
        img4tool::ASN1DERElement pramdisk = img4tool::ASN1DERElement(im4p, im4pSize, true);
        im4p = NULL;
        
        printf("Sending ramdisk...\n");
        auto sramdisk = img4FromIM4PandIM4M(pramdisk,im4m);
        idev.sendComponent(sramdisk.buf(), sramdisk.size());
        idev.sendCommand("ramdisk");
    }
    
    if (cfg.ra1nra1nPath) {
        FILE *f = NULL;
        char *im4p = NULL;
        cleanup([&]{
            safeFree(im4p);
            safeFreeCustom(f, fclose);
        });
        size_t im4pSize = 0;
        printf("Loading payload at=%s\n",cfg.ra1nra1nPath);
        
        assure(f = fopen(cfg.ra1nra1nPath, "rb"));
        fseek(f, 0, SEEK_END);
        assure(im4pSize = ftell(f));
        fseek(f, 0, SEEK_SET);
        assure(im4p = (char*)malloc(im4pSize));
        assure(fread(im4p, 1, im4pSize, f) == im4pSize);
                
        printf("Sending payload...\n");

        std::string loadAddr = idev.getEnv("loadaddr");
        idev.sendComponent(im4p, im4pSize);

        std::string memcpyCommand = "memcpy 0x828000000 ";
        memcpyCommand += loadAddr;
        memcpyCommand += " 0x800000";

        idev.sendCommand(memcpyCommand);
    }

    printf("Sending kernel...\n");
    auto skernel = img4FromIM4PandIM4M(pkernel,im4m);
    idev.sendComponent(skernel.buf(), skernel.size());

    if (!cfg.nobootx) {
        printf("Booting...\n");
        idev.setCheckpoint();
        idev.sendCommand("bootx");
        idev.waitForDisconnect(5000);
    }

    printf("Done!\n");
}


void ra1nsn0w::dumpAPTicket(iOSDevice &idev, const char* shshOutPath){
    char *buffer = NULL;
    cleanup([&]{
        safeFree(buffer);
    });
    int ret = 0;
    buffer = (char*)malloc(0x800000);
    memset(buffer, 0, 0x800000);

    idev.sendCommand("setenv filesize 0x0");
    ret = idev.usbReceive(buffer, 0x800000);


    memset(buffer, 0, 0x800000);
    idev.sendCommand("setenv filesize 0x800000");
    idev.sendCommand("memload");
    ret = idev.usbReceive(buffer, 0x800000);

    
    
    
    

    reterror("todo");
}
