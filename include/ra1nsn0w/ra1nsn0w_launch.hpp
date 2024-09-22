//
//  ra1nsn0w_launch.h
//  ra1nsn0w
//
//  Created by tihmstar on 22.09.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#ifndef ra1nsn0w_launch_h
#define ra1nsn0w_launch_h

#include <ra1nsn0w/ra1nsn0w_defs.hpp>
#include <ra1nsn0w/iOSDevice.hpp>

#include <img4tool/img4tool.hpp>

namespace tihmstar {
    namespace ra1nsn0w{
        std::map<uint32_t,std::vector<patchfinder::patch>> launchDevice(iOSDevice &idev, std::string firmwareUrl, const launchConfig &cfg = {}, img4tool::ASN1DERElement im4mData = {}, std::string variant = "");
    };
};


#endif /* ra1nsn0w_launch_h */
