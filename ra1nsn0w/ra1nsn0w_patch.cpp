//
//  ra1nsn0w_patch.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 22.09.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#include "../include/ra1nsn0w/ra1nsn0w_patch.hpp"
#include "../include/ra1nsn0w/ra1nsn0w_plugins.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder32.hpp>
#include <img3tool/img3tool.hpp>

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

#define addKernelpatch(cfgname, funcname, funcstring) \
                    if (cfg->cfgname) { \
                        if ((cfg->cfgname & (kPatchcfgYes | kPatchcfgMayFail)) \
                            || (cfg->is32Bit && (cfg->cfgname & (kPatchcfg32Yes | kPatchcfg32MayFail))) \
                            || (!cfg->is32Bit && (cfg->cfgname & (kPatchcfg64Yes | kPatchcfg64MayFail))) ){\
                            info("Kernel: Adding " funcstring " patch...\n"); \
                            try { \
                                auto patch = kpf->funcname(); \
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

int ra1nsn0w::patchFunciBoot(void *iBootBuf, size_t iBootBufSize, bootconfig *bcfg){
    patchfinder::ibootpatchfinder *ibpf = nullptr;
    cleanup([&]{
        safeDelete(ibpf);
    });

    const launchConfig *cfg = bcfg->launchcfg;
    std::vector<patchfinder::patch> patches;

    if (cfg->is32Bit) {
        ibpf = patchfinder::ibootpatchfinder32::make_ibootpatchfinder32(iBootBuf,iBootBufSize);
    }else{
        ibpf = patchfinder::ibootpatchfinder64::make_ibootpatchfinder64(iBootBuf,iBootBufSize);
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
        auto ppatches = p.second->patcher(bcfg->curPatchComponent, iBootBuf, iBootBufSize);
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
        uint8_t *pbuf = (uint8_t*)iBootBuf;
        memcpy(&pbuf[off], p.getPatch(), p.getPatchSize());
    }
    info("iBoot: Patches applied!");
    return 0;
}

int ra1nsn0w::patchFuncKernel(void *kernelBuf, size_t kernelBufSize, bootconfig *bcfg){
    std::vector<patchfinder::patch> patches;
    patchfinder::kernelpatchfinder *kpf = nullptr;
    cleanup([&]{
        safeDelete(kpf);
    });
    const launchConfig *cfg = bcfg->launchcfg;

    
    if (cfg->is32Bit) {
        kpf = patchfinder::kernelpatchfinder32::make_kernelpatchfinder32(kernelBuf,kernelBufSize);
    }else{
        kpf = patchfinder::kernelpatchfinder64::make_kernelpatchfinder64(kernelBuf,kernelBufSize);
    }
    
    if (cfg->doJailbreakPatches){
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
    
    if (cfg->kernelHardcodeBootargs.size()) {
        info("Kernel: Adding hardcode boot-arg patch (%s) ...",cfg->kernelHardcodeBootargs.c_str());
        auto patch = kpf->get_harcode_bootargs_patch(cfg->kernelHardcodeBootargs.c_str());
        patches.insert(patches.end(), patch.begin(), patch.end());
    }

    if (cfg->kernelHardcoderoot_ticket_hash.size()) {
        std::string pretty;
        for (int i=0; i<cfg->kernelHardcoderoot_ticket_hash.size(); i++) {
            char buf[0x10] = {};
            snprintf(buf, sizeof(buf), "%02x",cfg->kernelHardcoderoot_ticket_hash.data()[i]);
            pretty += buf;
        }
        info("Kernel: Adding hardcode boot-manifest patch (%s) ...",pretty.c_str());
        auto patch = kpf->get_harcode_boot_manifest_patch(cfg->kernelHardcoderoot_ticket_hash.data(),cfg->kernelHardcoderoot_ticket_hash.size());
        patches.insert(patches.end(), patch.begin(), patch.end());
    }

    if (cfg->replacePatches.find('nrkr') != cfg->replacePatches.end()) {
        auto replacePatches = cfg->replacePatches.at('nrkr');
        for (auto &r : replacePatches) {
            auto patch = kpf->get_replace_string_patch(r.first, r.second);
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        info("Inserted replacepatches for rkrn!");
    }
    
    if (cfg->replacePatches.find('nrek') != cfg->replacePatches.end()) {
        auto replacePatches = cfg->replacePatches.at('nrek');
        for (auto &r : replacePatches) {
            auto patch = kpf->get_replace_string_patch(r.first, r.second);
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        info("Inserted replacepatches for kern!");
    }
    try {
        auto userpatches = cfg->userPatches.at('nrkr'); //check if we have custom user patches for this component
        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
        info("Kernel: Inserted custom userpatches for rkrn!");
    } catch (...) {
        //
    }
    try {
        auto userpatches = cfg->userPatches.at('nrek'); //check if we have custom user patches for this component
        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
        info("Kernel: Inserted custom userpatches for kern!");
    } catch (...) {
        //
    }

    for (auto p : cfg->activePlugins) {
        auto ppatches = p.second->patcher('rkrn', kernelBuf, kernelBufSize);
        patches.insert(patches.end(), ppatches.begin(), ppatches.end());
    }
    
    /* ---------- Applying collected patches ---------- */
    info("Kernel: Applying patches...");
    bcfg->appliedPatches[bcfg->curPatchComponent] = patches;
    for (auto p : patches) {
        uint8_t *pbuf = (uint8_t*)kernelBuf;
        uint64_t off = (uint64_t)((const uint8_t *)kpf->memoryForLoc(p._location) - pbuf);
#ifdef DEBUG
        printf("kernel: Applying patch=%p : ",(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
#endif
        memcpy(&pbuf[off], p.getPatch(), p.getPatchSize());
    }
    
    info("Kernel: Patches applied!");
    return 0;
}

void ra1nsn0w::exportPatchesToJson(std::map<uint32_t,std::vector<patchfinder::patch>> patches, const char *outfilePath){
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

img4tool::ASN1DERElement ra1nsn0w::patchIMG4(const void *buf, size_t bufSize, const char *ivstr, const char *keystr, std::string findstr, std::function<int(void *, size_t, void *)> patchfunc, void *param){
    const char *usedCompression = NULL;
    img4tool::ASN1DERElement hypervisor{{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal},NULL,0};
    
    img4tool::ASN1DERElement im4p(buf,bufSize);
    
    img4tool::ASN1DERElement payload = getPayloadFromIM4P(im4p, ivstr, keystr, &usedCompression, &hypervisor);
    
    if (findstr.size()){
        //check if decryption was successfull
        retassure(memmem(payload.payload(), payload.payloadSize(), findstr.c_str() , findstr.size()), "Failed to find '%s'. Assuming decryption failed!",findstr.c_str());
    }

    assure(payload.ownsBuffer());
    
    //patch here
    if (patchfunc) {
        assure(!patchfunc((void*)payload.payload(), payload.payloadSize(), param));
    }
    
    img4tool::ASN1DERElement patchedIM4P = img4tool::getEmptyIM4PContainer(im4p[1].getStringValue().c_str(), im4p[2].getStringValue().c_str());
    
    {
#warning BUG WORKAROUND recompressing images with bvx2 makes them not boot for some reason
        if (usedCompression && strcmp(usedCompression, "bvx2") == 0) {
            warning("BUG WORKAROUND recompressing images with bvx2 makes them not boot for some reason. Skipping compression");
            usedCompression = NULL;
        }
    }
    
    return img4tool::appendPayloadToIM4P(patchedIM4P, payload.payload(), payload.payloadSize(), usedCompression, hypervisor.payload(), hypervisor.payloadSize());
}

tihmstar::Mem ra1nsn0w::patchIMG3(const void *buf, size_t bufSize, const char *ivstr, const char *keystr, std::string findstr, std::function<int(void *, size_t, void*)> patchfunc, void *param){
    const char *usedCompression = NULL;
    
    auto payload = img3tool::getPayloadFromIMG3(buf, bufSize, ivstr, keystr, &usedCompression);
    
    if (findstr.size()){
        //check if decryption was successfull
        retassure(memmem(payload.data(), payload.size(), findstr.c_str() , findstr.size()), "Failed to find '%s'. Assuming decryption failed!",findstr.c_str());
    }
    //patch here
    if (patchfunc) {
        assure(!patchfunc(payload.data(), payload.size(), param));
    }

    auto newpayload = img3tool::replaceDATAinIMG3({buf,bufSize}, payload, usedCompression);
    return img3tool::removeTagFromIMG3(newpayload.data(), newpayload.size(), 'KBAG');
}
