//
//  iOSDevice.cpp
//  ra1nsn0w
//
//  Created by tihmstar on 09.11.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "../include/ra1nsn0w/iOSDevice.hpp"
#include <chrono>
#include <unistd.h>
#include <string.h>
#include <map>
#include <tsschecker/tsschecker.hpp>

#define IBOOT_FLAG_IMAGE4_AWARE  1 << 2

using namespace tihmstar;
using namespace tihmstar::ra1nsn0w;

#ifndef HAVE_MEMMEM
void *memmem(const void *haystack_start, size_t haystack_len, const void *needle_start, size_t needle_len){
    const unsigned char *haystack = (const unsigned char *)haystack_start;
    const unsigned char *needle = (const unsigned char *)needle_start;
    const unsigned char *h = NULL;
    const unsigned char *n = NULL;
    size_t x = needle_len;

    /* The first occurrence of the empty string is deemed to occur at
    the beginning of the string.  */
    if (needle_len == 0) {
        return (void *)haystack_start;
    }

    /* Sanity check, otherwise the loop might search through the whole
        memory.  */
    if (haystack_len < needle_len) {
        return NULL;
    }

    for (; *haystack && haystack_len--; haystack++) {
        x = needle_len;
        n = needle;
        h = haystack;

        if (haystack_len < needle_len)
            break;

        if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
            continue;

        for (; x; h++, n++) {
            x--;

            if (*h != *n)
                break;

            if (x == 0)
                return (void *)haystack;
        }
    }
    return NULL;
}
#endif


#pragma mark callbacks

void tihmstar::ra1nsn0w::irecv_event_cb(const irecv_device_event_t* event, void *userdata) noexcept{
    iOSDevice *idev = (iOSDevice*)userdata;
    
    if (event->type == IRECV_DEVICE_ADD) {
        if (!idev->_ecid) {
            idev->_ecid = event->device_info->ecid;
            debug("IRECV_DEVICE_ADD: set ecid to %llu\n",idev->_ecid);
        }

        if ((idev->_ecid && event->device_info->ecid == idev->_ecid) || event->mode == IRECV_K_WTF_MODE) {
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
        if (event->device_info->ecid == idev->_ecid && (idev->_ecid || idev->_mode == iOSDevice::wtf)) {
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
iOSDevice::iOSDevice(uint64_t ecid, bool waitForDevice, std::string dryRunDevice, std::string dryRunOutPath)
    : _irecv_e_ctx(NULL), _mode(unknown), _ecid(ecid), _cli(NULL), _didDisconnect(false), _dryRunOutPath(dryRunOutPath), _dryRunDeviceSupportsIMG4(false)
{
    if (_dryRunOutPath.size()) {
        if (_dryRunOutPath.back() != '/') _dryRunOutPath.push_back('/');
    }
    
    if (dryRunDevice.size()) {
        ssize_t colonpos = dryRunDevice.find(":");
        ssize_t colonpos2 = dryRunDevice.find(":",colonpos+1);
        retassure(colonpos != std::string::npos && colonpos2 != std::string::npos, "Bad dryRunDevice. Specify like this 'iPhone6,2:n53ap:1' (device:model:supportsimg4)");
        _dryRunDeviceProductType = dryRunDevice.substr(0,colonpos);
        _dryRunDeviceHardwareModel = dryRunDevice.substr(colonpos+1, colonpos2-(colonpos+1));
        _dryRunDeviceSupportsIMG4 = atoi(dryRunDevice.substr(colonpos2+1).c_str());
        info("[DRY RUN] emulating device %s %s (%s)",_dryRunDeviceProductType.c_str(),_dryRunDeviceHardwareModel.c_str(),_dryRunDeviceSupportsIMG4 ? "IMG4" : "IMG3");
        _mode = iOSDevice::dfu;
        return;
    }

    retassure(!irecv_device_event_subscribe(&_irecv_e_ctx, irecv_event_cb, this),"Failed to subscribe to libirecovery device events");
    std::unique_lock<std::mutex> elock(_eventLock);

    // check which mode the device is currently in so we know where to start
    info("Waiting for device...\n");
    if (waitForDevice) {
        _eventNotifier.wait(elock, [&]{return _mode != iOSDevice::unknown;});
    }else{
        _eventNotifier.wait_for(elock, std::chrono::seconds(3), [&]{return _mode != iOSDevice::unknown;});
    }
    if (_mode == iOSDevice::unknown) {
        //do manual listing in case we missed an event
        struct irecv_device_info dinfo = {};
        int mode = 0;
        {
            //try to find an ecid
            irecv_client_t cli = {};
            cleanup([&]{
                safeFreeCustom(cli, irecv_close);
            });
            if (!irecv_open_with_ecid(&cli, 0)){
                //we could successfully open a device!
                if (const struct irecv_device_info* info = irecv_get_device_info(cli)){
                    //and we could get some info
                    dinfo = *info;
                    irecv_get_mode(cli, &mode);
                }
            }
        }
        
        if (dinfo.ecid) {
            //we have an ecid, which means there is a device! now manually construct an event
            irecv_device_event_t manualEvent = {
                .type = IRECV_DEVICE_ADD,
                .mode = (enum irecv_mode)mode,
                .device_info = &dinfo
            };
            {
                elock.unlock();
                cleanup([&]{
                    elock.lock();
                });
                irecv_event_cb(&manualEvent, this);
            }
        }
    }
    retassure(_mode != iOSDevice::unknown ,"ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
    retassure(_mode == iOSDevice::dfu || _mode == iOSDevice::recovery || _mode == iOSDevice::wtf, "ERROR: Device 0x%016llx is not in DFU or recovery mode\n",_ecid);
    elock.unlock();
    
    retassure(!irecv_open_with_ecid(&_cli, _ecid), "Failed to open connection to device");
    info("Found device: %s\n",getDeviceProductType().c_str());
}

iOSDevice::~iOSDevice(){
    safeFreeCustom(_cli, irecv_close);
    safeFreeCustom(_irecv_e_ctx, irecv_device_event_unsubscribe);
}

iOSDevice::devicemode iOSDevice::getDeviceMode(){
    return _mode;
}

std::string iOSDevice::getDeviceProductType(){
    if (_dryRunDeviceProductType.size()) {
        info("[DRY RUN] product type %s",_dryRunDeviceProductType.c_str());
        return _dryRunDeviceProductType;
    }
    irecv_device_t device = NULL;
    assure(!irecv_devices_get_device_by_client(_cli,&device));
    return device->product_type;
}

std::string iOSDevice::getDeviceHardwareModel(){
    if (_dryRunDeviceHardwareModel.size()) {
        info("[DRY RUN] hardware model %s",_dryRunDeviceHardwareModel.c_str());
        return _dryRunDeviceHardwareModel;
    }
    irecv_device_t device = NULL;
    assure(!irecv_devices_get_device_by_client(_cli,&device));
    return device->hardware_model;
}

uint32_t iOSDevice::getDeviceCPID(){
    if (_dryRunDeviceHardwareModel.size()) {
        return tsschecker::getCPIDForBoardType(_dryRunDeviceHardwareModel.c_str());
    }
    return irecv_get_device_info(_cli)->cpid;
}

uint32_t iOSDevice::getDeviceBDID(){
    if (_dryRunDeviceHardwareModel.size()) {
        return tsschecker::getBDIDForBoardType(_dryRunDeviceHardwareModel.c_str());
    }
    return irecv_get_device_info(_cli)->bdid;
}

uint64_t iOSDevice::getDeviceECID(){
    if (_dryRunDeviceHardwareModel.size()) {
        reterror("virtual ECID not implemented!");
    }
    return irecv_get_device_info(_cli)->ecid;
}

std::vector<uint8_t> iOSDevice::getAPNonce(){
    const irecv_device_info *info = irecv_get_device_info(_cli);
    return {info->ap_nonce,info->ap_nonce+info->ap_nonce_size};
}

std::vector<uint8_t> iOSDevice::getSEPNonce(){
    const irecv_device_info *info = irecv_get_device_info(_cli);
    return {info->sep_nonce,info->sep_nonce+info->sep_nonce_size};
}

bool iOSDevice::supportsIMG4(){
    if (_dryRunDeviceHardwareModel.size()) {
        info("[DRY RUN] supports IMG4: %s",_dryRunDeviceSupportsIMG4 ? "YES" : "NO");
        return _dryRunDeviceSupportsIMG4;
    }
    const struct irecv_device_info *info = NULL;
    retassure(info = irecv_get_device_info(_cli),"Failed to get deviceinfo");
    return (info->ibfl & IBOOT_FLAG_IMAGE4_AWARE);
}

void iOSDevice::sendComponent(const void *buf, size_t size){
    if (_dryRunOutPath.size()){
        static int componentnum = 0;
        size_t fnameSize = _dryRunOutPath.size() + sizeof("%scomponent%d.bin") + 100;
        char fname[fnameSize];
        memset(fname, 0, fnameSize);
        snprintf(fname, fnameSize, "%scomponent%d.bin",_dryRunOutPath.c_str(),++componentnum);
        FILE *f = fopen(fname, "wb");
        fwrite(buf, 1, size, f);
        fclose(f);
    }
    if (_dryRunDeviceHardwareModel.size()) {
        if (memmem(buf, size, "rd=md0", sizeof("rd=md0")-1) || memmem(buf, size, "iBEC for", sizeof("iBEC for")-1) || memmem(buf, size, "iBootStage2 for", sizeof("iBootStage2 for")-1)) {
            //we sent iBoot. We emulate to always boot straight to recovers
            info("[DRY RUN] sending buffer (iBoot detected, changing mode to recovery)");
            _mode = recovery;
        }else{
            info("[DRY RUN] sending buffer");
        }
        return;
    }
    irecv_error_t err = IRECV_E_SUCCESS;
    usleep(200);
    retassure(!(err = irecv_send_buffer(_cli, (unsigned char*)buf, size, 1)),"failed to send buffer");
}

void iOSDevice::setCheckpoint(){
    _didDisconnect = false;
}

void iOSDevice::waitForReconnect(uint32_t timeoutMS){
    if (_dryRunDeviceHardwareModel.size()) {
        info("[DRY RUN] reconnecting");
        return;
    }
    std::unique_lock<std::mutex> elock(_eventLock);
    irecv_error_t irecv_err = IRECV_E_SUCCESS;
    safeFreeCustom(_cli, irecv_close);

    if (!_didDisconnect) {
        _eventNotifier.wait_for(elock, std::chrono::milliseconds(timeoutMS), [&]{return _mode == iOSDevice::unknown;});
    }
    retassure(_didDisconnect, "Device did not disconnect");
    
    if (_mode == iOSDevice::unknown) { //if it is still disconnected
        _eventNotifier.wait_for(elock, std::chrono::milliseconds(timeoutMS), [&]{return _mode != iOSDevice::unknown;});
    }
    retassure(_mode == iOSDevice::dfu || _mode == iOSDevice::recovery, "Device did not reconnect");

    for (int i=0; i<10; i++) {
        if (!(irecv_err = irecv_open_with_ecid(&_cli, _ecid))) break;
        usleep(420);
    }
    
    retassure(!irecv_err, "Failed to reconnect to device with err=%d",irecv_err);
}

void iOSDevice::waitForDisconnect(uint32_t timeoutMS){
    if (_dryRunDeviceHardwareModel.size()) {
        info("[DRY RUN] disconnecting");
        _mode = unknown;
        return;
    }
    std::unique_lock<std::mutex> elock(_eventLock);
    safeFreeCustom(_cli, irecv_close);

    if (!_didDisconnect) {
        _eventNotifier.wait_for(elock, std::chrono::milliseconds(timeoutMS), [&]{return _mode == iOSDevice::unknown;});
    }
    retassure(_didDisconnect, "Device did not disconnect");
}


void iOSDevice::sendCommand(std::string command){
    if (_dryRunDeviceHardwareModel.size()) {
        info("[DRY RUN] sending command %s",command.c_str());
        return;
    }
    retassure(_mode == iOSDevice::recovery, "sendCommand called, but device is not in recovery mode");
    int isbreq = 0;
    if (command == "bootx" || command == "reset" || command == "go") isbreq = 1;
    retassure(!irecv_send_command_breq(_cli, command.c_str(),isbreq), "failed to send command");
}

std::string iOSDevice::getEnv(std::string env){
    if (_dryRunDeviceHardwareModel.size()) {
        std::string reply{""};
        static std::map<std::string,std::string> replies = {
            {"loadaddr","0x766972746c6472"}
        };
        try {reply = replies.at(env);} catch (...) {}
        info("[DRY RUN] running 'getenv %s', replying with '%s'",env.c_str(),reply.c_str());
        return reply;
    }
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
    r = irecv_usb_bulk_transfer(_cli, 0x81, (unsigned char*) buffer, (int)size, &bytes, 5000);
    irecv_usb_set_interface(_cli, 0, 0);
    return bytes;
}
