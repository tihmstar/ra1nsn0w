//
//  ra1nsn0w_argparse.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 22.01.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#include "../include/ra1nsn0w/ra1nsn0w.hpp"
#include "../include/ra1nsn0w/ra1nsn0w_plugins.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <libgeneral/Mem.hpp>

#include <set>

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

PluginObj::~PluginObj(){
    //
}

static struct option defaultLongopts[] = {
    /* Device selectors: */
    { "help",                           no_argument,            NULL, 'h' },
    { "apticket",                       required_argument,      NULL, 't' },
    { "buildid",                        required_argument,      NULL, 'B' },
    { "ecid",                           required_argument,      NULL, 'e' },
    { "wait",                           no_argument,            NULL, 'w' },
    { "32bit",                          no_argument,            NULL,  0  },
    { "dry-run",                        required_argument,      NULL,  0  },
    { "dry-out",                        required_argument,      NULL,  0  },
    { "export-patches",                 required_argument,      NULL,  0  },
    { "keys-zip",                       required_argument,      NULL,  0  },
    { "ota",                            no_argument,            NULL,  0  },

    /* Behavior config: */
    { "variant",                        required_argument,      NULL, 'V' },
    { "nobootx",                        no_argument,            NULL,  0  },
    { "just-dfu",                       no_argument,            NULL,  0  },
    { "just-iboot",                     no_argument,            NULL,  0  },
    { "decrypt-devicetree",             no_argument,            NULL,  0  },
    { "iboot-as-ibec",                  no_argument,            NULL,  0  },
    { "no-sep",                         no_argument,            NULL,  0  },
    { "no-decrypt",                     no_argument,            NULL,  0  },
    { "send-all-components",            no_argument,            NULL,  0  },
    { "srd",                            no_argument,            NULL,  0  },

    /* Customized boot: */
    { "fpatch",                         required_argument,      NULL,  0  },
    { "kernel",                         required_argument,      NULL, 'k' },
    { "ramdisk",                        required_argument,      NULL, 'r' },
    { "sep",                            required_argument,      NULL, 's' },
    { "trustcache",                     required_argument,      NULL, 'c' },
    { "logo",                           required_argument,      NULL, 'l' },
    { "custom-component",               required_argument,      NULL,  0  },
    { "ibec",                           required_argument,      NULL,  0  },
    { "ibss",                           required_argument,      NULL,  0  },
    { "patch",                          required_argument,      NULL,  0  },
    { "sreplace",                       required_argument,      NULL,  0  },

    /* iBEC patches: */
    { "boot-args",                      required_argument,      NULL, 'b' },
    { "iboot-nopatch",                  no_argument,            NULL,  0  },
    { "iboot-no-sigpatch",              no_argument,            NULL,  0  },
    { "iboot-send-signed-sep",          optional_argument,      NULL,  0  },
    { "ipatch-add-rw-and-rx-mappings",  optional_argument,      NULL,  0  },
    { "ipatch-atv4k-enable-uart",       optional_argument,      NULL,  0  },
    { "ipatch-always-production",       optional_argument,      NULL,  0  },
    { "ipatch-always-sepfw-booted",     optional_argument,      NULL,  0  },
    { "ipatch-cmdcall",                 required_argument,      NULL,  0  },
    { "ipatch-cmdhandler",              required_argument,      NULL,  0  },
    { "ipatch-disable-wxn-el3",         optional_argument,      NULL,  0  },
    { "ipatch-dtre-debug-enable",       optional_argument,      NULL,  0  },
    { "ipatch-no-force-dfu",            optional_argument,      NULL,  0  },
    { "ipatch-largepicture",            optional_argument,      NULL,  0  },
    { "ipatch-memcpy",                  optional_argument,      NULL,  0  },
    { "ipatch-nvram-unlock",            optional_argument,      NULL,  0  },
    { "ipatch-sep-force-local",         optional_argument,      NULL,  0  },
    { "ipatch-sep-force-raw",           optional_argument,      NULL,  0  },
    { "ipatch-sep-skip-bpr",            optional_argument,      NULL,  0  },
    { "ipatch-sep-skip-lock",           optional_argument,      NULL,  0  },
    { "ipatch-wtf-pwndfu",              optional_argument,      NULL,  0  },
    { "ra1nra1n",                       required_argument,      NULL,  0  },
    
    /* Kernel patches: */
    { "kernel-nopatch",                 no_argument,            NULL,  0  },
    { "kpatch-codesignature",           optional_argument,      NULL,  0  },
    { "kpatch-mount",                   optional_argument,      NULL,  0  },
    { "kpatch-sandbox",                 optional_argument,      NULL,  0  },
    { "kpatch-nuke-sandbox",            optional_argument,      NULL,  0  },
    { "kpatch-i_can_has_debugger",      no_argument,            NULL,  0  },
    { "kpatch-force-nand-writeable",    optional_argument,      NULL,  0  },
    { "kpatch-always-get-task-allow",   optional_argument,      NULL,  0  },
    { "kpatch-allow-uid",               optional_argument,      NULL,  0  },
    { "kpatch-add-read-bpr",            optional_argument,      NULL,  0  },
    { "kpatch-no-ramdisk-detect",       optional_argument,      NULL,  0  },
    { "kpatch-noemf",                   optional_argument,      NULL,  0  },
    { "kpatch-get-kernelbase-syscall",  optional_argument,      NULL,  0  },
    { "kpatch-tfp0",                    optional_argument,      NULL,  0  },
    { "kpatch-tfp-unrestrict",          optional_argument,      NULL,  0  },
    { "kpatch-setuid",                  optional_argument,      NULL,  0  },
    { "kpatch-force-boot-ramdisk",      optional_argument,      NULL,  0  },
    { "kpatch-hardcode-bootargs",       required_argument,      NULL,  0  },
    { "kpatch-hardcode-boot-manifest-hash",required_argument,   NULL,  0  },
    { "kpatch-root-from-sealed-apfs",   optional_argument,      NULL,  0  },
    { "kpatch-apfs-skip-authenticated-root-hash",optional_argument,NULL,  0  },
    { "sn0wsn0w",                       no_argument,            NULL,  0  },
    
    { NULL, 0, NULL, 0 }
};

static const char defaultHelpScreen[] =
"Usage: ra1nsn0w [OPTIONS] [IPSW]\n" \
"Multipurpose tool for launching custom bootchain\n\n" \
"Device selectors:\n" \
"  -h, --help\t\t\t\t\tDisplays this helpscreen\n" \
"  -t, --apticket PATH\t\t\t\tApticket use for bypassing sigchecks (Note: current sigcheck patches require an APTicket)\n" \
"  -B  --buildid BUILDID\t\t\t\tspecific buildid instead of iOS ipsw path\n" \
"  -e, --ecid ECID\t\t\t\tTarget specific device by its device ECID\n" \
"  -w, --wait\t\t\t\t\tWait for device\n" \
"      --32bit\t\t\t\t\tUse 32bit patchfinder instead of 64bit\n" \
"      --dry-run <device>:<hardware>:<img4>\tTest all patches, but don't actually send anything to device. Emulate device (eg. iPhone6,2:n53ap:1)\n" \
"      --dry-out <path>\t\t\t\tInstead of sending components to device, write them to the specified directory\n" \
"      --export-patches <patches.json>\t\tExport patches to a json file\n" \
"      --keys-zip <path>\t\t\t\tSpecify a zip file containing key json data, instead of using an online database or local server\n" \
"      --ota\t\t\t\t\tFirmwarefile is ota.zip rather than firmware.ipsw\n" \
"\nBehavior config:\n" \
"  -V, --variant <VARIANT>\t\t\tSpecify restore variant to use\n" \
"      --decrypt-devicetree\t\t\tSend devicetree decrypted (Usually we wouldn't touch that)\n" \
"      --iboot-as-ibect\t\t\t\tBoot iBoot instead of iBEC\n" \
"      --just-dfu\t\t\t\tStop in DFU mode\n" \
"      --just-iboot\t\t\t\tOnly boot to iBoot, do not send anything to it\n" \
"      --nobootx\t\t\t\t\tDon't run \"bootx\" command\n" \
"      --no-decrypt\t\t\t\tDo not decrypt files\n" \
"      --no-sep\t\t\t\t\tDo not boot rsep\n" \
"      --srd\t\t\t\t\tRequest ticket on-the-fly (for SRD)\n" \
"\nCustomized boot:\n" \
"  -k, --kernel <path>\t\t\t\tManually specify a kernel.im4p to boot\n" \
"  -r, --ramdisk <path>\t\t\t\tManually specify a ramdisk.im4p to boot\n" \
"  -s, --sep <path>\t\t\t\tManually specify a sep.im4p to boot\n" \
"  -c, --trustcache <path>\t\t\tManually specify a .trustcache to boot\n" \
"  -l, --logo <path>\t\t\t\tSpecify bootlogo\n" \
"      --custom-component=<component>,<path>\tManually specify a firmware component\n" \
"      --fpatch=<component>:<addr1>,<file>\tManually specify a patch to a component from file\n" \
"      --ibec <path>\t\t\t\tManually specify a iBEC to boot\n" \
"      --ibss <path>\t\t\t\tManually specify a iBSS to boot\n" \
"      --patch=<component>:<addr1>,<patch1>\tManually specify a patch to a component\n" \
"      --send-all-components\t\tSend all components that iboot expects\n" \
"      --sreplace=<component>:<findstr,replacestr>;... Patch replace string with other string\n" \
"\niBEC patches:\n" \
"  -b, --boot-args ARGS\t\t\t\tSpecify kernel bootargs\n" \
"      --iboot-nopatch\t\t\t\tDon't modify iBoot (iBSS/iBEC) IM4P and send as it is (only rename to rkrn)\n" \
"      --iboot-no-sigpatch\t\t\tDon't apply iBSS/iBEC sigpatches (WARNING: device will not boot past this bootloader!)\n" \
"      --iboot-send-signed-sep\tGet a valid ticket and send RestoreSEP\n" \
"      --ipatch-add-rw-and-rx-mappings\t\tSets iBoot block writeable at 0x2000000 and loadaddr block executable at 0x4000000\n" \
"      --ipatch-always-production\t\tPretend we're in production mode even though we may be demoted\n" \
"      --ipatch-always-sepfw-booted\t\tAlways set 'sepfw-booted' in devicetree\n" \
"      --ipatch-atv4k-enable-uart\t\tPinmux and enable UART on ATV4k\n" \
"      --ipatch-cmdcall NAME\t\t\tPatch command NAME to be an arbitrary call gadget\n" \
"      --ipatch-cmdhandler NAME=VALUE\t\tPatch command NAME to jump to VALUE\n" \
"            (Example --cmdhandler go=0x41414141 makes go command jump to address 0x41414141)\n" \
"      --ipatch-disable-wxn-el3\t\t\tDisable WXN enforcement in EL3 iBoot\n" \
"      --ipatch-dtre-debug-enable\t\tSet debug-enable in devicetree\n" \
"      --ipatch-no-force-dfu\t\t\tSkip iBoot force_dfu checks\n" \
"      --ipatch-largepicture\t\t\tRemove setpicture's sizelimit of 0x100000 bytes\n" \
"      --ipatch-memcpy\t\t\t\tReplace reboot with memcpy\n" \
"      --ipatch-nvram-unlock\t\t\tAllows reading and writing all nvram vars\n" \
"      --ipatch-sep-force-local\t\t\tForce booting sepi instead of rsep\n" \
"      --ipatch-sep-force-raw\t\t\tForce loading raw rsep\n" \
"      --ipatch-sep-skip-bpr\t\t\tDon't set SEP BPR by iBoot\n" \
"      --ipatch-sep-skip-lock\t\t\tDon't lock tz0 registers by iBoot\n" \
"      --ipatch-wtf-pwndfu\t\t\tPatch WTF image to act as PWNDFU\n" \
"      --ra1nra1n <path>\t\t\t\tExecute payload before jumping to kernel\n" \
"\nKernel patches:\n" \
"     --kernel-nopatch\t\t\t\tDon't modify kernel IM4P and send as it is (only rename to rkrn)\n" \
"     --kpatch-add-read-bpr\t\t\tAllow reading BPR status by overwriting syscall 213\n" \
"     --kpatch-allow-uid\t\t\t\tAllow using UID key for enc/dec from userspace\n" \
"     --kpatch-always-get-task-allow\t\tMake all processes have get-task-allow entitlement\n" \
"     --kpatch-apfs-skip-authenticated-root-hash Skip checking for authenticated root hash\n" \
"     --kpatch-codesignature\t\t\tAllow unsigned code to run\n" \
"     --kpatch-force-boot-ramdisk\t\tAlways imply 'rd=md0' even if that bootarg is not set\n" \
"     --kpatch-force-nand-writeable\t\tMake NAND writeable even in ramdisk boot\n" \
"     --kpatch-get-kernelbase-syscall\t\tSyscall 213 to return kernelbase\n" \
"     --kpatch-hardcode-bootargs ARGS\t\tSpecify kernel bootargs (to be hardcoded inside the kernel)\n" \
"     --kpatch-hardcode-boot-manifest-hash\tARGS Specify boot-manifest-hash (to be hardcoded inside the kernel)\n" \
"     --kpatch-i_can_has_debugger\t\tPatch i_can_has_debugger = 1\n" \
"     --kpatch-mount\t\t\t\tAllow mounting / as rw\n" \
"     --kpatch-no-ramdisk-detect\t\t\tPatch detection of 'rd=md0' in kernel\n" \
"     --kpatch-noemf\t\t\t\tDisable kernel EMF decryption\n" \
"     --kpatch-nuke-sandbox\t\t\tCompletely nuke sanbox by nulling ALL mac_policy_ops fields\n" \
"     --kpatch-root-from-sealed-apfs\t\tAllow rooting from sealed live APFS\n" \
"     --kpatch-sandbox\t\t\t\tNeuter sanbox by nulling common mac_policy_ops fields\n" \
"     --kpatch-setuid\t\t\t\tRe-add setuid functionality to kernel\n" \
"     --kpatch-tfp0\t\t\t\tAllow calling task_for_pid(0)\n" \
"     --kpatch-tfp-unrestrict\t\t\tAllow anyone calling task_for_pid()\n" \
"     --sn0wsn0w\t\t\t\t\tApply generic kernelpatches\n" \
"\n" \
;


#ifndef HAVE_STRTOUL_L
#define strtoul_l _strtoul_l
#endif

#ifndef LC_GLOBAL_LOCALE
# define LC_GLOBAL_LOCALE ((_locale_t)-1) //this is for windows :/
#endif

static bool defaultparseArgument(launchConfig &cfg, std::string curopt, const char *optarg){
#define parsePatchConfig(name,val) if (curopt == name) cfg.val = RA1NSN0W_PARSE_PATCH_CONFIG
    //device selectors
    if (curopt == "32bit") {
        cfg.is32Bit = true;
    }else if (curopt == "ota") {
        cfg.isOtaFirmware = true;
    }
    //behavior config
    else if (curopt == "decrypt-devicetree") {
        cfg.decrypt_devicetree = true;
    }else if (curopt == "iboot-as-ibec") {
        cfg.boot_iboot_instead_of_ibec = true;
    }else if (curopt == "just-dfu") {
        cfg.justDFU = true;
    }else if (curopt == "just-iboot") {
        cfg.justiBoot = true;
    }else if (curopt == "nobootx") {
        cfg.nobootx = true;
    }else if (curopt == "no-decrypt") {
        cfg.noDecrypt = true;
    }else if (curopt == "no-sep") {
        cfg.boot_no_sep = true;
    }else if (curopt == "srd") {
        cfg.isSRD = true;
    }
    //Customized boot
    else if (curopt == "custom-component") {
        parserCustomComponent(optarg, cfg);
    }else if (curopt == "ibec") {
        cfg.iBECIm4p = readFile(optarg);
    }else if (curopt == "ibss") {
        cfg.iBSSIm4p = readFile(optarg);
    }else if (curopt == "patch" || curopt == "fpatch") {
        parserUserPatch(optarg, cfg, curopt == "fpatch");
    }else if (curopt == "send-all-components") {
        cfg.sendAllComponents = true;
    }else if (curopt == "sreplace") {
        parserStringReplacePatch(optarg, cfg);
    }
    //iBEC patches
    else if (curopt == "iboot-nopatch") {
        cfg.iboot_nopatch = true;
    }
    else if (curopt == "iboot-no-sigpatch") {
        cfg.no_iboot_sigpatch = true;
    }
    else if (curopt == "iboot-send-signed-sep") {
        if (optarg) cfg.iboot_send_signed_sep = optarg;
        else cfg.iboot_send_signed_sep.push_back('\0');
    }
    else parsePatchConfig("ipatch-add-rw-and-rx-mappings",iboot_add_rw_and_rx_mappings);
    else parsePatchConfig("ipatch-always-production",iboot_always_production);
    else parsePatchConfig("ipatch-always-sepfw-booted",iboot_always_sepfw_booted);
    else parsePatchConfig("ipatch-atv4k-enable-uart",iboot_atv4k_enable_uart);
    else if (curopt == "ipatch-cmdcall") {
        cfg.cmdcall = optarg;
    }else if (curopt == "ipatch-cmdhandler") {
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
    else parsePatchConfig("ipatch-dtre-debug-enable",iboot_dtre_debug_enable);
    else parsePatchConfig("ipatch-disable-wxn-el3",iboot_disable_wxn_el3);
    else parsePatchConfig("ipatch-no-force-dfu",iboot_no_force_dfu);
    else parsePatchConfig("ipatch-largepicture",iboot_largepicture);
    else parsePatchConfig("ipatch-memcpy",iboot_reboot_to_memcpy);
    else if (curopt == "ipatch-nvram-unlock"){
        cfg.nobootx = true;
        cfg.iboot_nvramUnlock = kPatchcfgYes;
    }
    else parsePatchConfig("ipatch-sep-force-local",iboot_sep_force_local);
    else parsePatchConfig("ipatch-sep-force-raw",iboot_sep_force_raw);
    else parsePatchConfig("ipatch-sep-skip-bpr",iboot_sep_skip_bpr);
    else parsePatchConfig("ipatch-sep-skip-lock",iboot_sep_skip_lock);
    else parsePatchConfig("ipatch-wtf-pwndfu",wtf_pwndfu);
    else if (curopt == "ra1nra1n") {
        cfg.ra1nra1n = readFile(optarg);
    }
    //Kernel patches
    else if (curopt == "kernel-nopatch") {
        cfg.kernel_nopatch = true;
    }
    else parsePatchConfig("kpatch-add-read-bpr",kpatch_add_read_bpr);
    else parsePatchConfig("kpatch-allow-uid",kpatch_allow_uid);
    else parsePatchConfig("kpatch-always-get-task-allow",kpatch_always_get_task_allow);
    else parsePatchConfig("kpatch-apfs-skip-authenticated-root-hash",kpatch_apfs_skip_authenticated_root);
    else parsePatchConfig("kpatch-codesignature",kpatch_codesig);
    else parsePatchConfig("kpatch-force-boot-ramdisk",kpatch_force_boot_ramdisk);
    else parsePatchConfig("kpatch-force-nand-writeable",kpatch_force_nand_writeable);
    else parsePatchConfig("kpatch-get-kernelbase-syscall",kpatch_get_kernelbase_syscall);
    else if (curopt == "kpatch-hardcode-bootargs") {
        cfg.kernelHardcodeBootargs = optarg;
    }else if (curopt == "kpatch-hardcode-boot-manifest-hash") {
        size_t len = strlen(optarg);
        if (len & 1){
            error("Failed reading hexbytes!");
            return -1;
        }
        cfg.kernelHardcoderoot_ticket_hash.resize(len/2);
        for (size_t i = 0; i<len; i+=2) {
            uint32_t byte = 0;
            assure(sscanf(&optarg[i], "%02x",&byte) == 1);
            cfg.kernelHardcoderoot_ticket_hash.data()[i/2] = (uint8_t)byte;
        }
    }
    else parsePatchConfig("kpatch-i_can_has_debugger",kpatch_i_can_has_debugger);
    else parsePatchConfig("kpatch-mount",kpatch_mount);
    else parsePatchConfig("kpatch-no-ramdisk-detect",kpatch_no_ramdisk_detect);
    else parsePatchConfig("kpatch-noemf",kpatch_noemf);
    else parsePatchConfig("kpatch-nuke-sandbox",kpatch_nuke_sandbox);
    else parsePatchConfig("kpatch-root-from-sealed-apfs",kpatch_root_from_sealed_apfs);
    else parsePatchConfig("kpatch-sandbox",kpatch_sandbox);
    else parsePatchConfig("kpatch-setuid",kpatch_setuid);
    else parsePatchConfig("kpatch-tfp0",kpatch_tfp0);
    else parsePatchConfig("kpatch-tfp-unrestrict",kpatch_tfp_unrestrict);
    else if (curopt == "sn0wsn0w") {
        cfg.doJailbreakPatches = true;
    }else{
        return false;
    }
    
    return true;
}

#pragma mark helper vars
static tihmstar::Typed_Mem<struct option> gLongopts;
static std::string gCmdHelperString;
static std::set<const Plugin*> gPlugins;

static void updateCmdHelperString(void){
    gCmdHelperString.clear();
    gCmdHelperString += defaultHelpScreen;
    gCmdHelperString += "------------ PLUGINS ------------\n";
    for (auto p : gPlugins) {
        gCmdHelperString += p->cmdHelp;
        gCmdHelperString += "\n";
    }
}

static void updateLongopts(void){
    gLongopts.mem().resize(0);
    gLongopts.mem().append(defaultLongopts, sizeof(defaultLongopts)-sizeof(*defaultLongopts));
    
    for (auto p : gPlugins) {
        for (const struct option *opt = p->longopts; opt->name; opt++) {
            struct option lopt = *opt;
            lopt.flag = NULL;
            lopt.val = 0;
            gLongopts.mem().append(&lopt,sizeof(lopt));
        }
    }
    
    struct option nullopt = {};
    gLongopts.mem().append(&nullopt,sizeof(nullopt));
}

#pragma mark public
const char *ra1nsn0w::getShortOpts(void){
    return "ht:B:e:wv:k:r:s:c:l:b:V:";
}

const struct option *ra1nsn0w::getLongOpts(void){
    return gLongopts.mem().size() > sizeof(defaultLongopts) ? gLongopts : defaultLongopts;
}

const char *ra1nsn0w::getCmdHelpString(void){
    return gCmdHelperString.size() ? gCmdHelperString.c_str() : defaultHelpScreen;
}

#pragma mark argparser
bool ra1nsn0w::parseArgument(launchConfig &cfg, std::string curopt, const char *optarg){
    if (defaultparseArgument(cfg, curopt, optarg)) return true;
    for (auto p : gPlugins) {
        std::shared_ptr<PluginObj> po = cfg.activePlugins[p];
        if (po == nullptr){
            po = cfg.activePlugins[p] = p->init();
        }
        if (po->argparse(curopt, optarg)) return true;
    }
    return false;
}

void ra1nsn0w::pluginRegister(const Plugin *plugin){
#ifdef WITH_PLUGIN_SUPPORT
    gPlugins.insert(plugin);
    updateCmdHelperString();
    updateLongopts();
#else
    error("ra1nsn0w::pluginRegister called, but ra1nsn0w was built without plugin support!");
#endif //WITH_PLUGIN_SUPPORT
}

void ra1nsn0w::pluginUnregister(const Plugin *plugin){
#ifdef WITH_PLUGIN_SUPPORT
    gPlugins.erase(plugin);
    updateCmdHelperString();
    updateLongopts();
#else
    error("ra1nsn0w::pluginUnregister called, but ra1nsn0w was built without plugin support!");
#endif //WITH_PLUGIN_SUPPORT
}
