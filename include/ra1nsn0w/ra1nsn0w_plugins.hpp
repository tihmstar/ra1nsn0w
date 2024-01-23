//
//  ra1nsn0w_plugins.hpp
//  ra1nsn0w
//
//  Created by tihmstar on 22.01.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#ifndef ra1nsn0w_plugins_h
#define ra1nsn0w_plugins_h


#include <ra1nsn0w/iOSDevice.hpp>
#include <ra1nsn0w/ra1nsn0w.hpp>
#include <img4tool/img4tool.hpp>
#include <libpatchfinder/patch.hpp>

#include <map>

#include <getopt.h>

namespace tihmstar {
    namespace ra1nsn0w{
        class PluginObj{
        public:
            virtual ~PluginObj();
            virtual bool argparse(std::string longopt, const char *optarg) = 0;
            virtual std::vector<patchfinder::patch> patcher(uint32_t component, const void *buf, size_t bufSize) = 0;
        };
    
        typedef bool (*f_argparse_t)(void *param, std::string longopt, const char *optarg);
        typedef std::vector<patchfinder::patch> (*f_patcher_t)(void *param, uint32_t component, const void *buf, size_t bufSize);
        typedef std::shared_ptr<PluginObj>(*f_constructor)();

        struct Plugin{
            const char *cmdHelp;
            const struct option *longopts;
            f_constructor init;
        };
#pragma mark argparser
    
        bool parseArgument(launchConfig &cfg, std::string longopt, const char *optarg);

#pragma mark argparser helper
        void parserUserPatch(std::string userpatch, launchConfig &cfg, bool isFile = false);
        void parserCustomComponent(std::string customcomponent, launchConfig &cfg);
        void parserStringReplacePatch(std::string userpatch, launchConfig &cfg);

#pragma mark Plugins
        const char *getShortOpts(void);
        const struct option *getLongOpts(void);
        const char *getCmdHelpString(void);
    
        void pluginRegister(const Plugin *plugin);
        void pluginUnregister(const Plugin *plugin);
    };
};

#define RA1NSN0W_PARSE_PATCH_CONFIG ((!optarg) ? kPatchcfgYes : ((!strcmp(optarg, "optional")) ? kPatchcfgMayFail : (Patchcfg)atoi(optarg)))


#endif /* ra1nsn0w_plugins_h */
