//
//  ra1nsn0w_defs.hpp
//  ra1nsn0w
//
//  Created by tihmstar on 22.09.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#ifndef ra1nsn0w_defs_h
#define ra1nsn0w_defs_h

#include <libgeneral/Mem.hpp>
#include <libpatchfinder/patch.hpp>

#include <iostream>
#include <map>
#include <vector>

namespace tihmstar {
    namespace ra1nsn0w{
        class Plugin;
        class PluginObj;
        enum Patchcfg{
            kPatchcfgNo = 0,
            kPatchcfgYes = 1,
            kPatchcfgMayFail = 2,

            //only apply for 32bit devices
            kPatchcfg32Yes = 4,
            kPatchcfg32MayFail = 8,

            //only apply for 64bit devices
            kPatchcfg64Yes = 16,
            kPatchcfg64MayFail = 32,
        };
    
        struct launchConfig{
            bool is32Bit = false;
            bool isOtaFirmware = false;
            bool doJailbreakPatches = false;
            bool justDFU = false;
            bool justiBoot = false;
            bool iboot_nopatch = false;
            bool kernel_nopatch = false;
            bool decrypt_devicetree = false;
            bool nobootx = false;
            bool no_iboot_sigpatch = false;
            bool boot_iboot_instead_of_ibec = false;
            bool boot_no_sep = false;
            bool setAutobootFalse = false;
            bool noDecrypt = false;
            bool sendAllComponents = false;
            bool isSRD = false;
            bool restoreBoot = false;

            std::string customKeysZipUrl = "";

            std::string iboot_send_signed_sep = "";

            Patchcfg wtf_pwndfu = kPatchcfgNo;
            
            Patchcfg iboot_nvramUnlock = kPatchcfgNo;
            Patchcfg iboot_add_rw_and_rx_mappings = kPatchcfgNo;
            Patchcfg iboot_disable_wxn_el3 = kPatchcfgNo;
            Patchcfg iboot_sep_skip_lock = kPatchcfgNo;
            Patchcfg iboot_sep_skip_bpr = kPatchcfgNo;
            Patchcfg iboot_reboot_to_memcpy = kPatchcfgNo;
            Patchcfg iboot_largepicture = kPatchcfgNo;
            Patchcfg iboot_sep_force_local = kPatchcfgNo;
            Patchcfg iboot_sep_force_raw = kPatchcfgNo;
            Patchcfg iboot_atv4k_enable_uart = kPatchcfgNo;
            Patchcfg iboot_always_production = kPatchcfgNo;
            Patchcfg iboot_always_sepfw_booted = kPatchcfgNo;
            Patchcfg iboot_no_force_dfu = kPatchcfgNo;
            Patchcfg iboot_dtre_debug_enable = kPatchcfgNo;

            Patchcfg kpatch_codesig = kPatchcfgNo;
            Patchcfg kpatch_mount = kPatchcfgNo;
            Patchcfg kpatch_sandbox = kPatchcfgNo;
            Patchcfg kpatch_nuke_sandbox = kPatchcfgNo;
            Patchcfg kpatch_i_can_has_debugger = kPatchcfgNo;
            Patchcfg kpatch_force_nand_writeable = kPatchcfgNo;
            Patchcfg kpatch_always_get_task_allow = kPatchcfgNo;
            Patchcfg kpatch_allow_uid = kPatchcfgNo;
            Patchcfg kpatch_add_read_bpr = kPatchcfgNo;
            Patchcfg kpatch_no_ramdisk_detect = kPatchcfgNo;
            Patchcfg kpatch_noemf = kPatchcfgNo;
            Patchcfg kpatch_get_kernelbase_syscall = kPatchcfgNo;
            Patchcfg kpatch_tfp0 = kPatchcfgNo;
            Patchcfg kpatch_tfp_unrestrict = kPatchcfgNo;
            Patchcfg kpatch_setuid = kPatchcfgNo;
            Patchcfg kpatch_force_boot_ramdisk = kPatchcfgNo;
            Patchcfg kpatch_root_from_sealed_apfs = kPatchcfgNo;
            Patchcfg kpatch_apfs_skip_authenticated_root = kPatchcfgNo;
            
            tihmstar::Mem root_ticket_hash;
            tihmstar::Mem kernelHardcoderoot_ticket_hash;
            std::vector<std::pair<std::string, uint64_t>> cmdhandler;
            std::string cmdcall;
            std::string bootargs;
            std::string kernelHardcodeBootargs;

            tihmstar::Mem kernelIm4p;
            tihmstar::Mem ramdiskIm4p;
            tihmstar::Mem sepIm4p;
            tihmstar::Mem ra1nra1n;
            tihmstar::Mem trustcache;
            tihmstar::Mem bootlogoIm4p;
            tihmstar::Mem iBSSIm4p;
            tihmstar::Mem iBECIm4p;
            bool ramdiskIsRawDMG = false;
            
            std::map<const Plugin*,std::shared_ptr<PluginObj>> activePlugins;
            
            std::map<uint32_t,std::vector<patchfinder::patch>> userPatches; // <component,patches>
            std::map<uint32_t,std::vector<std::pair<std::string,std::string>>> replacePatches; // <find str, replace str>
            std::map<std::string,tihmstar::Mem> customComponents; // <componentName, data>
        };
    
        struct bootconfig{
            const launchConfig *launchcfg;
            bool didProcessKernelLoader;
            bool skipiBEC;
            uint32_t curPatchComponent;
            std::map<uint32_t,std::vector<patchfinder::patch>> appliedPatches;
        };
    };
};

#endif /* ra1nsn0w_defs_h */
