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
#include <libpatchfinder/txmpatchfinder/txmpatchfinder64.hpp>
#include <img3tool/img3tool.hpp>

#ifdef HAVE_RAMDISK_PATCHER
#include <Ramdisk/Ramdisk.hpp>
#include <RamdiskPatcher/RPPF.hpp>
#include <RamdiskPatcher/utils.hpp>
#endif //HAVE_RAMDISK_PATCHER

#include <string.h>

#define ASR_RAMDISK_PATH "/usr/sbin/asr"
#define LIBIMG4_RAMDISK_PATH "/usr/lib/libimg4.dylib"
#define RESTORED_RAMDISK_PATH "/usr/local/bin/restored_external"

#ifndef HAVE_MEMMEM
static void *memmem(const void *haystack_start, size_t haystack_len, const void *needle_start, size_t needle_len){
    const unsigned char *haystack = (const unsigned char *)haystack_start;
    const unsigned char *needle = (const unsigned char *)needle_start;
    const unsigned char *h = NULL;
    const unsigned char *n = NULL;
    size_t x = needle_len;

    /* The first occurrence of the empty string is deemed to occur at
    the beginning of the string.  */
    if (needle_len == 0) {
        return (void *)haystack_start;
    }

    /* Sanity check, otherwise the loop might search through the whole
        memory.  */
    if (haystack_len < needle_len) {
        return NULL;
    }

    for (; haystack_len--; haystack++) {
        x = needle_len;
        n = needle;
        h = haystack;

        if (haystack_len < needle_len)
            break;

        if ((haystack[0] != needle[0]) || (haystack[needle_len-1] != needle[needle_len-1]))
            continue;

        for (; x--; h++, n++) {
            if (*h != *n) break;
            if (x == 0) return (void *)haystack;
        }
    }
    return NULL;
}
#endif

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

#define addTXMpatch(cfgname, funcname, funcstring) \
                    if (cfg->cfgname) { \
                        if ((cfg->cfgname & (kPatchcfgYes | kPatchcfgMayFail)) \
                            || (cfg->is32Bit && (cfg->cfgname & (kPatchcfg32Yes | kPatchcfg32MayFail))) \
                            || (!cfg->is32Bit && (cfg->cfgname & (kPatchcfg64Yes | kPatchcfg64MayFail))) ){\
                            info("TXM: Adding " funcstring " patch...\n"); \
                            try { \
                                auto patch = txmpf->funcname(); \
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

int ra1nsn0w::patchFuncDevicetree(void *dtreBuf, size_t dtreBufSize, bootconfig *bcfg){
    const launchConfig *cfg = bcfg->launchcfg;
    std::vector<patchfinder::patch> patches;
  
    if (cfg->replacePatches.find(bcfg->curPatchComponent) != cfg->replacePatches.end()) {
        auto replacePatches = cfg->replacePatches.at(bcfg->curPatchComponent);
        for (auto &r : replacePatches) {
            retassure(r.first.size() == r.second.size(), "patch and replace are different size!");
            uint8_t *tgt = (uint8_t*)dtreBuf;
            size_t tgtSize = dtreBufSize;
            while (tgt){
                uint8_t *found = (uint8_t*)memmem(tgt, tgtSize, r.first.data(), r.first.size());
                if (!found) break;
                patches.push_back({
                    (uint64_t)(found - (uint8_t*)dtreBuf),
                    r.second.data(),
                    r.second.size()
                });
                found++;
                tgtSize -= found-tgt;
                tgt = found;
            }
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
        auto ppatches = p.second->patcher(bcfg->curPatchComponent, dtreBuf, dtreBufSize);
        patches.insert(patches.end(), ppatches.begin(), ppatches.end());
    }
    
    /* ---------- Applying collected patches ---------- */
    bcfg->appliedPatches[bcfg->curPatchComponent] = patches;
    info("Devicetree: Applying patches...");
    for (auto p : patches) {
        uint64_t off = (uint64_t)(p._location);
#ifdef DEBUG
        printf("Devicetree: Applying patch=%p : ",(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
#endif
        uint8_t *pbuf = (uint8_t*)dtreBuf;
        retassure(off+p.getPatchSize()<dtreBufSize, "devicetree patch is OOB");
        memcpy(&pbuf[off], p.getPatch(), p.getPatchSize());
    }
    info("Devicetree: Patches applied!");
    return 0;
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
    addiBootpatch(iboot_always_production, get_always_production_patch, "get_always_production_patch")

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
        addiBootpatch(iboot_no_img3_dumplist, get_no_img3_dumplist_patch, "get_no_img3_dumplist_patch")
        addiBootpatch(iboot_sep_skip_lock, get_tz0_lock_patch, "get_tz0_lock_patch")
        addiBootpatch(iboot_sep_skip_bpr, get_skip_set_bpr_patch, "get_skip_set_bpr_patch")
        addiBootpatch(iboot_sep_force_local, get_force_septype_local_patch, "get_force_septype_local_patch")
        addiBootpatch(iboot_sep_force_raw, get_sep_load_raw_patch, "get_sep_load_raw_patch")
        addiBootpatch(iboot_largepicture, get_large_picture_patch, "get_large_picture_patch")
        addiBootpatch(iboot_atv4k_enable_uart, get_atv4k_enable_uart_patch, "get_atv4k_enable_uart_patch")
        addiBootpatch(iboot_always_sepfw_booted, get_always_sepfw_booted_patch, "get_always_sepfw_booted_patch")
        addiBootpatch(iboot_no_force_dfu, get_no_force_dfu_patch, "get_no_force_dfu_patch")
        addiBootpatch(iboot_honor_bootargs, get_honor_nvram_boot_arg_patch, "get_honor_nvram_boot_arg_patch")
        addiBootpatch(iboot_dtre_debug_enable, get_debug_enabled_patch, "get_debug_enabled_patch")

        
        if (cfg->root_ticket_hash.size())            {
            info("iBoot: Adding root_ticket_hash patch...");
            auto patch = ibpf->set_root_ticket_hash(cfg->root_ticket_hash.data(), cfg->root_ticket_hash.size());
            patches.insert(patches.end(), patch.begin(), patch.end());
        }

        if (cfg->boot_manifest_hash.size())            {
            info("iBoot: Adding boot_manifest_hash patch...");
            auto patch = ibpf->set_boot_manifest_hash(cfg->boot_manifest_hash.data(), cfg->boot_manifest_hash.size());
            patches.insert(patches.end(), patch.begin(), patch.end());
        }

        if (cfg->ra1nra1n.size()){
            {
                info("iBoot: Adding ra1nra1n patch...");
                auto patch = ibpf->get_ra1nra1n_patch();
                patches.insert(patches.end(), patch.begin(), patch.end());
            }
            {
                info("iBoot: Adding replace_cmd_with_ra1nra1n patch...");
                auto patch = ibpf->replace_cmd_with_ra1nra1n("reboot");
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
#ifdef HAVE_RAMDISK_PATCHER
        if (bcfg->launchcfg->rpatch_asr_hardcodepw){
            info("iBoot: Getting platform-name ...");
            bcfg->platform = ibpf->get_platform_name();
        }
#endif
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
        addKernelpatch(kpatch_no_nonce_entanglement, get_no_nonce_entanglement_patch, "get_no_nonce_entanglement_patch");
        addKernelpatch(kpatch_noemf, get_noemf_patch, "get_noemf_patch");
        addKernelpatch(kpatch_get_kernelbase_syscall, get_kernelbase_syscall_patch, "get_kernelbase_syscall_patch");
        addKernelpatch(kpatch_tfp0, get_tfp0_patch, "get_tfp0_patch");
        addKernelpatch(kpatch_tfp_unrestrict, get_tfp_anyone_allow_patch, "get_tfp_anyone_allow_patch");
        addKernelpatch(kpatch_setuid, get_insert_setuid_patch, "get_insert_setuid_patch");
        addKernelpatch(kpatch_force_boot_ramdisk, get_force_boot_ramdisk_patch, "get_force_boot_ramdisk_patch");
        addKernelpatch(kpatch_root_from_sealed_apfs, get_apfs_root_from_sealed_livefs_patch, "get_apfs_root_from_sealed_livefs_patch");
        addKernelpatch(kpatch_apfs_skip_authenticated_root, get_apfs_skip_authenticate_root_hash_patch, "get_apfs_skip_authenticate_root_hash_patch");
        addKernelpatch(kpatch_allow_sep_boot_skip_stage1, get_allow_sep_boot_skip_stage1, "get_allow_sep_boot_skip_stage1");
        addKernelpatch(kpatch_sep_is_obliterating, get_sep_is_obliterating_patch, "get_sep_is_obliterating_patch");
        addKernelpatch(kpatch_img3nor_checks, get_AppleImage3NORAccess_sigcheck_patch, "get_AppleImage3NORAccess_sigcheck_patch");
        addKernelpatch(kpatch_lwvm, get_lwvm_rw_patch, "get_lwvm_rw_patch");
        addKernelpatch(kpatch_sandbox_label_update_execve, get_sandbox_label_update_execve_patch, "get_sandbox_label_update_execve_patch");
        addKernelpatch(kpatch_proc_enforce_disable, get_proc_enforce_disable_patch, "get_proc_enforce_disable_patch");
        addKernelpatch(kpatch_raw_sep_romcmd, get_raw_sep_romcmd_patch, "get_raw_sep_romcmd_patch");
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

int ra1nsn0w::patchFuncTXM(void *txmBuf, size_t txmBufSize, bootconfig *bcfg){
    std::vector<patchfinder::patch> patches;
    patchfinder::txmpatchfinder *txmpf = nullptr;
    cleanup([&]{
        safeDelete(txmpf);
    });
    const launchConfig *cfg = bcfg->launchcfg;

    txmpf = patchfinder::txmpatchfinder64::make_txmpatchfinder64(txmBuf, txmBufSize);
    
    {
        addTXMpatch(txm_codesig, get_codesignature_patches, "codesignature")
    }

    if (cfg->replacePatches.find('xrtr') != cfg->replacePatches.end()) {
        auto replacePatches = cfg->replacePatches.at('xrtr');
        for (auto &r : replacePatches) {
            auto patch = txmpf->get_replace_string_patch(r.first, r.second);
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        info("Inserted replacepatches for rtrx!");
    }

    if (cfg->replacePatches.find('mxrt') != cfg->replacePatches.end()) {
        auto replacePatches = cfg->replacePatches.at('mxrt');
        for (auto &r : replacePatches) {
            auto patch = txmpf->get_replace_string_patch(r.first, r.second);
            patches.insert(patches.end(), patch.begin(), patch.end());
        }
        info("Inserted replacepatches for trxm!");
    }
    try {
        auto userpatches = cfg->userPatches.at('xrtr'); //check if we have custom user patches for this component
        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
        info("Kernel: Inserted custom userpatches for rtrx!");
    } catch (...) {
        //
    }
    
    try {
        auto userpatches = cfg->userPatches.at('mxrt'); //check if we have custom user patches for this component
        patches.insert(patches.end(), userpatches.begin(), userpatches.end());
        info("Kernel: Inserted custom userpatches for trxm!");
    } catch (...) {
        //
    }

    for (auto p : cfg->activePlugins) {
        auto ppatches = p.second->patcher('xrtr', txmBuf, txmBufSize);
        patches.insert(patches.end(), ppatches.begin(), ppatches.end());
    }
    
    /* ---------- Applying collected patches ---------- */
    info("TXM: Applying patches...");
    bcfg->appliedPatches[bcfg->curPatchComponent] = patches;
    for (auto p : patches) {
        uint8_t *pbuf = (uint8_t*)txmBuf;
        uint64_t off = (uint64_t)((const uint8_t *)txmpf->memoryForLoc(p._location) - pbuf);
#ifdef DEBUG
        printf("TXM: Applying patch=%p : ",(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
#endif
        memcpy(&pbuf[off], p.getPatch(), p.getPatchSize());
    }
    
    info("TXM: Patches applied!");
    return 0;
}

tihmstar::Mem ra1nsn0w::patchFuncRamdisk(const void *rdBuf, size_t rdBufSize, bootconfig *bcfg){
#ifndef HAVE_RAMDISK_PATCHER
    reterror("Compiled without libRamdiskPatcher");
#else
    std::shared_ptr<Ramdisk::Ramdisk> ramdisk = Ramdisk::Ramdisk::make_ramdisk(rdBuf, rdBufSize);
    if (bcfg->launchcfg->rpatch_asr_sigcheck || bcfg->launchcfg->rpatch_asr_hardcodepw){
        tihmstar::Mem asr;
        std::vector<tihmstar::patchfinder::patch> asrPatches;
        std::shared_ptr<RamdiskPatcher::RPPF> asrPatcher;

        if (!asr.size()) asr = ramdisk->extractFile(ASR_RAMDISK_PATH);
        asrPatcher = RamdiskPatcher::RPPF::make_RPPF(asr.data(), asr.size());

        if (bcfg->launchcfg->rpatch_asr_sigcheck) {
            auto p = asrPatcher->getASRSigcheckPatches();
            asrPatches.insert(asrPatches.end(), p.begin(), p.end());
        }
        
        if (bcfg->launchcfg->rpatch_asr_hardcodepw) {
            retassure(bcfg->platform.size(), "Can't derive passp for unknown platform!");
            std::string passp = RamdiskPatcher::utils::genpassp(bcfg->platform.c_str(), rdBuf, rdBufSize);
            info("[RPObj] Rootfs pass: %s",passp.c_str());
            auto p = asrPatcher->getASRHardcodedPWPatches(passp.c_str());
            asrPatches.insert(asrPatches.end(), p.begin(), p.end());
        }
            
        if (asrPatches.size()) {
            asrPatcher->applyPatches(asrPatches);
            asr = RamdiskPatcher::utils::resignFile(asrPatcher->buf(), asrPatcher->bufSize());
            ramdisk->putFile(ASR_RAMDISK_PATH, asr.data(), asr.size());
        }
    }
    
    {
        tihmstar::Mem restored;
        std::vector<tihmstar::patchfinder::patch> restoredPatches;
        std::shared_ptr<RamdiskPatcher::RPPF> restoredPatcher;
        
        if (bcfg->launchcfg->rpatch_restored_sigcheck) {
            if (!restored.size()) restored = ramdisk->extractFile(RESTORED_RAMDISK_PATH);
            restoredPatcher = RamdiskPatcher::RPPF::make_RPPF(restored.data(), restored.size());
            {
                auto p = restoredPatcher->getRestoredSigcheckPatches();
                restoredPatches.insert(restoredPatches.end(), p.begin(), p.end());
            }
        }
            
        if (restoredPatches.size()) {
            restoredPatcher->applyPatches(restoredPatches);
            restored = RamdiskPatcher::utils::resignFile(restoredPatcher->buf(), restoredPatcher->bufSize());
            ramdisk->putFile(RESTORED_RAMDISK_PATH, restored.data(), restored.size());
        }
    }
    
    {
        tihmstar::Mem libimg4;
        std::vector<tihmstar::patchfinder::patch> libimg4Patches;
        std::shared_ptr<RamdiskPatcher::RPPF> libimg4Patcher;
        
        if (bcfg->launchcfg->rpatch_libimg4_sigcheck) {
            if (!libimg4.size()) libimg4 = ramdisk->extractFile(LIBIMG4_RAMDISK_PATH);
            libimg4Patcher = RamdiskPatcher::RPPF::make_RPPF(libimg4.data(), libimg4.size());
            {
                auto p = libimg4Patcher->getLibIMG4SigcheckPatches();
                libimg4Patches.insert(libimg4Patches.end(), p.begin(), p.end());
            }
        }
            
        if (libimg4Patches.size()) {
            libimg4Patcher->applyPatches(libimg4Patches);
            libimg4 = RamdiskPatcher::utils::resignFile(libimg4Patcher->buf(), libimg4Patcher->bufSize());
            ramdisk->putFile(LIBIMG4_RAMDISK_PATH, libimg4.data(), libimg4.size());
        }
    }
    
    if (bcfg->launchcfg->rpatch_delete_nvmefw){
        auto files = ramdisk->listFilesAtPath("/usr/standalone/firmware", true);
        for (auto f : files){
            if (f.ends_with(".pak")) ramdisk->rm(f.c_str());
        }
    }
    
    for (auto a : bcfg->launchcfg->rpatch_rdactions) {
        switch (a.type) {
            case kRDActionTypeDelete:
                info("[RPObj] Deleting '%s'",a.path.c_str());
                ramdisk->rm(a.path.c_str(), true);
                break;
            
            case kRDActionTypePut:
            {
                if (a.args.size()) {
                    std::string putsrc = a.path;
                    std::string putdst = a.args.at(0);
                    info("[RPObj] Putting file '%s' to '%s' in ramdisk",putsrc.c_str(),putdst.c_str());
                    auto f = tihmstar::readFile(putsrc.c_str());
                    ramdisk->putFile(putdst.c_str(), f.data(), f.size());
                }else{
                    std::string putdst = a.path;
                    info("[RPObj] Creating empty file '%s' in ramdisk",putdst.c_str());
                    ramdisk->putFile(putdst.c_str(), NULL, 0);
                }
            }
                break;
                
            default:
                reterror("Unhandled action type %d", a.type);
        }
    }
    
    return {ramdisk->buf(), ramdisk->bufSize()};
#endif //HAVE_RAMDISK_PATCHER
}

bool ra1nsn0w::wantsPatchingRamdisk(bootconfig *bcfg){
#ifdef HAVE_RAMDISK_PATCHER
    if (bcfg->launchcfg->rpatch_asr_sigcheck) return true;
    if (bcfg->launchcfg->rpatch_asr_hardcodepw) return true;
    if (bcfg->launchcfg->rpatch_libimg4_sigcheck) return true;
    if (bcfg->launchcfg->rpatch_restored_sigcheck) return true;
    if (bcfg->launchcfg->rpatch_delete_nvmefw) return true;
    if (bcfg->launchcfg->rpatch_rdactions.size()) return true;
#endif
    return false;
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
    
    auto ret = img4tool::appendPayloadToIM4P(patchedIM4P, payload.payload(), payload.payloadSize(), usedCompression, hypervisor.payload(), hypervisor.payloadSize());
    
    if (img4tool::im4pContainsPAYP(im4p)){
        auto payp = img4tool::getPAYPFromIM4P(im4p);
        ret = img4tool::appendPAYPToIM4P(ret, payp);
    }
    
    return ret;
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
