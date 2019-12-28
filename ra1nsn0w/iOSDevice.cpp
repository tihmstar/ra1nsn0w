//
//  iOSDevice.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "iOSDevice.hpp"
#include <chrono>
#include <unistd.h>

#ifdef DEBUG
#define debug(a...) printf(a)
#else
#define debug(a...) //
#endif


using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

#pragma mark callbacks

void tihmstar::ra1nsn0w::irecv_event_cb(const irecv_device_event_t* event, void *userdata) noexcept{
    iOSDevice *idev = (iOSDevice*)userdata;
    
    if (event->type == IRECV_DEVICE_ADD) {
        if (!idev->_ecid) {
            idev->_ecid = event->device_info->ecid;
            debug("IRECV_DEVICE_ADD: set ecid to %llu\n",idev->_ecid);
        }

        if (idev->_ecid && event->device_info->ecid == idev->_ecid) {
            idev->_eventLock.lock();
            switch (event->mode) {
                case IRECV_K_WTF_MODE:
                    idev->_mode = iOSDevice::wtf;
                    break;
                case IRECV_K_DFU_MODE:
                    idev->_mode = iOSDevice::dfu;
                    break;
                case IRECV_K_RECOVERY_MODE_1:
                case IRECV_K_RECOVERY_MODE_2:
                case IRECV_K_RECOVERY_MODE_3:
                case IRECV_K_RECOVERY_MODE_4:
                    idev->_mode = iOSDevice::recovery;
                    break;
                default:
                    idev->_mode = iOSDevice::unknown;
            }
            debug("IRECV_DEVICE_ADD: changed mode to %d\n",idev->_mode);
            idev->_eventLock.unlock();
            idev->_eventNotifier.notify_all();
        }
    } else if (event->type == IRECV_DEVICE_REMOVE) {
        if (idev->_ecid && event->device_info->ecid == idev->_ecid) {
            idev->_eventLock.lock();
            idev->_didDisconnect = true;
            idev->_mode = iOSDevice::unknown;
            idev->_eventLock.unlock();
            idev->_eventNotifier.notify_all();
            debug("IRECV_DEVICE_REMOVE: changed mode to %d\n",idev->_mode);
        }
    }
}

#pragma mark iOSDevice

iOSDevice::iOSDevice(uint64_t ecid) :
    #warning TODO INIT memvars
    _ecid(ecid),
    _cli(NULL)
{
    std::unique_lock<std::mutex> elock(_eventLock);
    retassure(!irecv_device_event_subscribe(&_irecv_e_ctx, irecv_event_cb, this),"Failed to subscribe to libirecovery device events");

    
    // check which mode the device is currently in so we know where to start
    printf("Waiting for device...\n");
    _eventNotifier.wait_for(elock, std::chrono::seconds(10));
    retassure(_mode != iOSDevice::unknown ,"ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
    retassure(_mode == iOSDevice::dfu || _mode == iOSDevice::recovery, "ERROR: Device 0x%016llx is not in DFU or recovery mode\n",_ecid);
    elock.unlock();
    
    retassure(!irecv_open_with_ecid(&_cli, _ecid), "Failed to open connection to device");
    printf("Found device: %s\n",getDeviceProductType().c_str());
}

iOSDevice::~iOSDevice(){
    if (_cli) {
        irecv_close(_cli);
    }
}

iOSDevice::devicemode iOSDevice::getDeviceMode(){
    return _mode;
}

std::string iOSDevice::getDeviceProductType(){
    irecv_device_t device = NULL;
    assure(!irecv_devices_get_device_by_client(_cli,&device));
    return device->product_type;
}

std::string iOSDevice::getDeviceHardwareModel(){
    irecv_device_t device = NULL;
    assure(!irecv_devices_get_device_by_client(_cli,&device));
    return device->hardware_model;
}

void iOSDevice::sendComponent(const void *buf, size_t size){
    irecv_error_t err = IRECV_E_SUCCESS;
    retassure(!(err = irecv_send_buffer(_cli, (unsigned char*)buf, size, 1)),"failed to send buffer");
}

void iOSDevice::setCheckpoint(){
    _didDisconnect = false;
}

void iOSDevice::waitForReconnect(uint32_t timeoutMS){
    std::unique_lock<std::mutex> elock(_eventLock);
    if (!_didDisconnect) {
        _eventNotifier.wait_for(elock, std::chrono::milliseconds(timeoutMS));
    }
    retassure(_didDisconnect, "Device did not disconnect");
    
    if (_mode == iOSDevice::unknown) { //if it is still disconnected
        _eventNotifier.wait_for(elock, std::chrono::milliseconds(timeoutMS));
    }
    retassure(_mode == iOSDevice::dfu || _mode == iOSDevice::recovery, "Device did not reconnect");
    irecv_close(_cli); _cli = NULL;
    
    retassure(!irecv_open_with_ecid(&_cli, _ecid), "Failed to reconnect to device");
}

void iOSDevice::waitForDisconnect(uint32_t timeoutMS){
    std::unique_lock<std::mutex> elock(_eventLock);
    if (!_didDisconnect) {
        _eventNotifier.wait_for(elock, std::chrono::milliseconds(timeoutMS));
    }
    retassure(_didDisconnect, "Device did not disconnect");
    irecv_close(_cli); _cli = NULL;
}


void iOSDevice::sendCommand(std::string command){
    retassure(_mode == iOSDevice::recovery, "sendCommand called, but device is not in recovery mode");
    retassure(!irecv_send_command(_cli, command.c_str()), "failed to send command");
}

std::string iOSDevice::getEnv(std::string env){
    char *val = NULL;
    cleanup([&]{
        safeFree(val);
    });
    retassure(_mode == iOSDevice::recovery, "sendCommand called, but device is not in recovery mode");
    retassure(!irecv_getenv(_cli, env.c_str(),&val), "failed to getenv");
    return val;
}


int iOSDevice::usbReceive(char *buffer, size_t size){
    int r;
    int bytes;
    irecv_usb_set_interface(_cli, 1, 1);
    r = irecv_usb_bulk_transfer(_cli, 0x81, (unsigned char*) buffer, size, &bytes, 5000);
    irecv_usb_set_interface(_cli, 0, 0);
    return bytes;
}
