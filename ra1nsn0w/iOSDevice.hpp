//
//  iOSDevice.hpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef iOSDevice_hpp
#define iOSDevice_hpp

#include <iostream>
#include <mutex>
#include <condition_variable>
extern "C"{
#include <libirecovery.h>
};

namespace tihmstar {
namespace ra1nsn0w{
            
    class iOSDevice{
    public:
#pragma mark public types
        enum devicemode{
            unknown,
            wtf,
            dfu,
            recovery,
            restore,
            normal
        };
        
#pragma mark private members
    private:
        irecv_device_event_context_t _irecv_e_ctx;
        devicemode _mode;
        uint64_t _ecid;
        std::mutex _eventLock;
        std::condition_variable _eventNotifier;
        irecv_client_t _cli;
        bool _didDisconnect;

#pragma mark public methods
    public:
        iOSDevice(uint64_t ecid = 0);
        ~iOSDevice();
        
        devicemode getDeviceMode();
        std::string getDeviceProductType();
        std::string getDeviceHardwareModel();

        void sendComponent(const void *buf, size_t size);
        void setCheckpoint();
        void waitForReconnect(uint32_t timeoutMS);
        void waitForDisconnect(uint32_t timeoutMS);

        void sendCommand(std::string command);
        std::string getEnv(std::string env);

        int usbReceive(char *buffer, size_t size);
        
#pragma mark public static functions
        friend void irecv_event_cb(const irecv_device_event_t* event, void *userdata) noexcept;
    };
};
};

#endif /* iOSDevice_hpp */
