//
//  ra1nsn0w_patch.hpp
//  ra1nsn0w
//
//  Created by tihmstar on 22.09.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#ifndef ra1nsn0w_patch_h
#define ra1nsn0w_patch_h

#include <ra1nsn0w/ra1nsn0w_defs.hpp>
#include <img4tool/img4tool.hpp>
#include <libgeneral/Mem.hpp>

namespace tihmstar {
    namespace ra1nsn0w{
        int patchFunciBoot(void *iBootBuf, size_t iBootBufSize, bootconfig *bcfg);
        int patchFuncKernel(void *kernelBuf, size_t kernelBufSize, bootconfig *bcfg);

        void exportPatchesToJson(std::map<uint32_t,std::vector<patchfinder::patch>> patches, const char *outfilePath);
    
        img4tool::ASN1DERElement patchIMG4(const void *buf, size_t bufSize, const char *ivstr, const char *keystr, std::string findstr, std::function<int(char *, size_t, void *)> patchfunc, void *param);
        tihmstar::Mem patchIMG3(const void *buf, size_t bufSize, const char *ivstr, const char *keystr, std::string findstr, std::function<int(char *, size_t, void*)> patchfunc, void *param);
    };
};


#endif /* ra1nsn0w_patch_h */
