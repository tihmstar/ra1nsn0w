//
//  ra1nsn0w.hpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef ra1nsn0w_hpp
#define ra1nsn0w_hpp

#include "iOSDevice.hpp"
#include <img4tool/img4tool.hpp>

namespace tihmstar {
    namespace ra1nsn0w{
    
        struct launchConfig{
            bool nobootx;
            bool nvramUnlock;
            bool apticketdump;
            std::pair<std::string, uint64_t> cmdhandler;
            std::string bootargs;
            const char *kernelIm4pPath;
            const char *ramdiskIm4pPath;
            const char *ra1nra1nPath;
        };

        void launchDevice(iOSDevice &idev, std::string firmwareUrl, const img4tool::ASN1DERElement &im4m, const launchConfig &cfg = {});
    
    
        void dumpAPTicket(iOSDevice &idev, const char* shshOutPath);
    
    };
};

#endif /* ra1nsn0w_hpp */
