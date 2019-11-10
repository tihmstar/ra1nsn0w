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
            std::pair<std::string, uint64_t> cmdhandler;
            std::string bootargs;
        };

        void launchDevice(iOSDevice &idev, std::string firmwareUrl, const img4tool::ASN1DERElement &im4m, const launchConfig &cfg = {});
    };
};

#endif /* ra1nsn0w_hpp */
