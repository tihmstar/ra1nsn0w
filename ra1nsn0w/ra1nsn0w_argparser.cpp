//
//  ra1nsn0w_argparser.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 22.01.24.
//  Copyright © 2024 tihmstar. All rights reserved.
//

#include "../include/ra1nsn0w/ra1nsn0w.hpp"
#include "../include/ra1nsn0w/ra1nsn0w_plugins.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

#pragma mark public
#pragma mark argparser helper
void ra1nsn0w::parserUserPatch(std::string userpatch, launchConfig &cfg, bool isFile){
    printf("Parsing custom user patch \"%s\"\n",userpatch.c_str());
    ssize_t colunpos = 0;
    uint32_t component = 0;

    retassure((colunpos = userpatch.find(":")) != std::string::npos, "Failed to find ':' What component is this patch for?");

    std::string componentstr = userpatch.substr(0,colunpos);
    std::string patchstr = userpatch.substr(colunpos+1);

    retassure(componentstr.size() == 4, "component needs to be 4 bytes in size");
    component = *(uint32_t*)componentstr.c_str();
    
    while (true) {
        tihmstar::Mem patchBytes;
        
        ssize_t nextPatchPos = patchstr.find(";");
        ssize_t commaPos = 0;
        assure((commaPos = patchstr.find(",")) != std::string::npos); //if we have a patch, we need at least <addr> and <patch>

        std::string pAddr = patchstr.substr(0,commaPos);
        std::string pPatch = patchstr.substr(commaPos+1,nextPatchPos);
        
        uint64_t addr = 0;
        assure(sscanf(pAddr.c_str(), "0x%llx",&addr) == 1);
        
        if (isFile) {
            patchBytes = readFile(pPatch.c_str());
        }else{
            patchBytes.resize(pPatch.size());
            for (size_t i = 0; i<pPatch.size(); i+=2) {
                uint32_t byte = 0;
                assure(sscanf(&pPatch.c_str()[i], "%02x",&byte) == 1);
                patchBytes.data()[i/2] = (uint8_t)byte;
            }
            patchBytes.resize(pPatch.size()/2);
        }

        patchfinder::patch p{addr,patchBytes.data(),patchBytes.size()};

        printf("%s: Parsed patch=%p : ",componentstr.c_str(),(void*)p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
        
        cfg.userPatches[component].push_back(p);
        
        if (nextPatchPos == std::string::npos) break;
        patchstr = patchstr.substr(nextPatchPos+1);
    }
}

void ra1nsn0w::parserCustomComponent(std::string customcomponent, launchConfig &cfg){
    printf("Parsing custom firmware paths \"%s\"\n",customcomponent.c_str());
    ssize_t commapos = 0;
    retassure((commapos = customcomponent.find(",")) != std::string::npos, "Failed to find ',' What component is this path for?");
    
    std::string componentName = customcomponent.substr(0,commapos);
    auto data = readFile(customcomponent.substr(commapos+1).c_str());
    cfg.customComponents[componentName] = std::move(data);
}

void ra1nsn0w::parserStringReplacePatch(std::string userpatch, launchConfig &cfg){
    printf("Parsing custom string replace patch \"%s\"\n",userpatch.c_str());
    ssize_t colunpos = 0;
    uint32_t component = 0;

    retassure((colunpos = userpatch.find(":")) != std::string::npos, "Failed to find ':' What component is this patch for?");

    std::string componentstr = userpatch.substr(0,colunpos);
    std::string patchstr = userpatch.substr(colunpos+1);

    retassure(componentstr.size() == 4, "component needs to be 4 bytes in size");
    component = *(uint32_t*)componentstr.c_str();
    
    while (true) {
        uint8_t *patchBytes = NULL;
        cleanup([&]{
            safeFree(patchBytes);
        });
        
        ssize_t nextPatchPos = patchstr.find(";");
        ssize_t commaPos = 0;
        assure((commaPos = patchstr.find(",")) != std::string::npos); //if we have a patch, we need at least <addr> and <patch>

        std::string pFind = patchstr.substr(0,commaPos);
        std::string pReplace = patchstr.substr(commaPos+1,nextPatchPos);

        printf("%s: Parsed repalce patch='%s'->'%s'\n",componentstr.c_str(),pFind.c_str(),pReplace.c_str());
        
        cfg.replacePatches[component].push_back({pFind,pReplace});
        
        if (nextPatchPos == std::string::npos) break;
        patchstr = patchstr.substr(nextPatchPos+1);
    }
}
