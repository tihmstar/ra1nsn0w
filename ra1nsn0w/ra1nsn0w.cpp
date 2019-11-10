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

extern "C"{
#include <libfragmentzip/libfragmentzip.h>
};


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

void ra1nsn0w::launchDevice(iOSDevice &idev, std::string firmwareUrl, const img4tool::ASN1DERElement &im4m, const launchConfig &cfg){
    fragmentzip_t *fzinfo = NULL;
    char *buildmanifestBuf = NULL;
    size_t buildmanifestBufSize = 0;
    plist_t buildmanifest = NULL;
    
    char *ibssPath = NULL;
    char *ibecPath = NULL;
    char *kernelPath = NULL;
    char *dtrePath = NULL;

    char *ibssBuf = NULL;   size_t ibssBufSize = 0;
    char *ibecBuf = NULL;   size_t ibecBufSize = 0;
    char *kernelBuf = NULL; size_t kernelBufSize = 0;
    char *dtreBuf = NULL;   size_t dtreBufSize = 0;
    
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
    bundle = libipatcher::getPwnBundleForDevice(idev.getDeviceProductType(),buildnum);
    
#pragma mark get path for components
    retassure(!build_identity_get_component_path(buildidentity, "iBSS", &ibssPath), "Failed to get iBSS Path from BuildIdentity");
    printf("Found iBSS at %s\n",ibssPath);

    retassure(!build_identity_get_component_path(buildidentity, "iBEC", &ibecPath), "Failed to get iBEC Path from BuildIdentity");
    printf("Found iBEC at %s\n",ibecPath);

    retassure(!build_identity_get_component_path(buildidentity, "KernelCache", &kernelPath), "Failed to get kernel Path from BuildIdentity");
    printf("Found kernel at %s\n",kernelPath);

    retassure(!build_identity_get_component_path(buildidentity, "DeviceTree", &dtrePath), "Failed to get DeviceTree Path from BuildIdentity");
    printf("Found DeviceTree at %s\n",dtrePath);
    
#pragma mark load components
    printf("Loading iBSS...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, ibssPath, &ibssBuf, &ibssBufSize, fragmentzip_callback),"Failed to load iBSS");
    
    printf("Loading iBEC...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, ibecPath, &ibecBuf, &ibecBufSize, fragmentzip_callback),"Failed to load iBEC");

    printf("Loading kernel...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, kernelPath, &kernelBuf, &kernelBufSize, fragmentzip_callback),"Failed to load kernel");

    printf("Loading DeviceTree...\n");
    retassure(!fragmentzip_download_to_memory(fzinfo, dtrePath, &dtreBuf, &dtreBufSize, fragmentzip_callback),"Failed to load DeviceTree");


#pragma mark patch components
    printf("Patching iBSS...\n");
    auto ppiBSS = libipatcher::patchiBSS(ibssBuf, ibssBufSize, bundle.iBSSKey);
    img4tool::ASN1DERElement piBSS{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    try {
        piBSS = {ppiBSS.first,ppiBSS.second, true}; //transfer ownership of buffer to ASN1DERElement
    } catch (tihmstar::exception &e) {
        safeFree(ppiBSS.first); //if transfer fails, free buffer
        throw;
    }
    ppiBSS = {};//if transfer succeeds, discard second copy of buffer
    
    printf("Patching iBEC...\n");
    auto ppiBEC = libipatcher::patchCustom(ibecBuf, ibecBufSize, bundle.iBECKey, [&cfg](char *file, size_t size, void *param)->int{
        std::vector<offsetfinder64::patch> patches;
        offsetfinder64::ibootpatchfinder64 ibpf(file,size);

        {
            printf("iBEC: Adding sigcheck patch...\n");
            auto patch = ibpf.get_sigcheck_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        {
            printf("iBEC: Adding debug_enable patch...\n");
            auto patch = ibpf.get_debug_enabled_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        {
            printf("iBEC: Adding boot-arg patch (%s) ...\n",cfg.bootargs.c_str());
            auto patch = ibpf.get_boot_arg_patch(cfg.bootargs.c_str());
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        if (cfg.cmdhandler.first.size()) {
            printf("iBEC: Adding cmdhandler patch (%s=0x%016llx) ...\n",cfg.cmdhandler.first.c_str(),cfg.cmdhandler.second);
            auto patch = ibpf.get_cmd_handler_patch(cfg.cmdhandler.first.c_str(),cfg.cmdhandler.second);
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        if (cfg.nvramUnlock) {
            printf("iBEC: Adding nvram_unlock patch...\n");
            auto patch = ibpf.get_unlock_nvram_patch();
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        
        
        /* ---------- Applying collected patches ---------- */
        for (auto p : patches) {
            offsetfinder64::offset_t off = (offsetfinder64::offset_t)(p._location - ibpf.find_base());
            printf("iBEC: Applying patch=%p : ",(void*)p._location);
            for (int i=0; i<p._patchSize; i++) {
                printf("%02x",((uint8_t*)p._patch)[i]);
            }
            printf("\n");
            memcpy(&file[off], p._patch, p._patchSize);
        }
        printf("iBEC: Patches applied!\n");
        return 0;
    }, NULL);
    img4tool::ASN1DERElement piBEC{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    try {
        piBEC = {ppiBEC.first,ppiBEC.second, true}; //transfer ownership of buffer to ASN1DERElement
    } catch (tihmstar::exception &e) {
        safeFree(ppiBEC.first); //if transfer fails, free buffer
        throw;
    }
    ppiBEC = {};//if transfer succeeds, discard second copy of buffer

    
    printf("Patching kernel...\n");
#warning TODO actual kernelpatching
    img4tool::ASN1DERElement pkernel{kernelBuf,kernelBufSize};
    pkernel = img4tool::renameIM4P(pkernel, "rkrn");

    
    printf("Patching DeviceTree...\n");
    img4tool::ASN1DERElement pdtre{dtreBuf,dtreBufSize};
    pdtre = img4tool::renameIM4P(pdtre, "rdtr");
    
    
#pragma mark stich APTicket and send
    
    printf("Sending iBSS...\n");
    auto siBSS = img4FromIM4PandIM4M(piBSS,im4m);
    idev.setCheckpoint();
    idev.sendComponent(siBSS.buf(), siBSS.size());
    if (idev.getDeviceMode() == iOSDevice::recovery) {
        //are we in pwn recovery already??
        idev.sendCommand("go");
    }
    idev.waitForReconnect(10000);

    printf("Sending iBEC...\n");
    auto siBEC = img4FromIM4PandIM4M(piBEC,im4m);
    idev.setCheckpoint();
    idev.sendComponent(siBEC.buf(), siBEC.size());
    idev.waitForReconnect(10000);

    retassure(idev.getDeviceMode() == iOSDevice::recovery, "Device failed to boot iBEC");
    
    idev.sendCommand("bgcolor 0 0 255");
    
    printf("Sending DeviceTree...\n");
    auto sdtre = img4FromIM4PandIM4M(pdtre,im4m);
    idev.sendComponent(sdtre.buf(), sdtre.size());
    idev.sendCommand("devicetree");


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
