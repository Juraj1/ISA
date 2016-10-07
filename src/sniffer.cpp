/****** my custom headers ******/
#include "sniffer.h"

#include <getopt.h>

/**
 * @file sniffer.cpp
 * @author Jiri Zahradnik <xzahra22>
 * @date 3rd October 2016
 * @brief Sniffer class implementation for ISA project.
 */

sniffer::sniffer() {
    mInterfaceFlag.first = false;
    mInterfaceFlag.second = "";

    mHelloFlag = false;

    mTtlFlag.first = false;
    mTtlFlag.second = -1;

    mDuplexFlag.first = false;
    mDuplexFlag.second = "";

    mPlatformFlag.first = false;
    mPlatformFlag.second = "";

    mVersionFlag.first = false;
    mVersionFlag.second = "";

    mDeviceIdFlag.first = false;
    mDeviceIdFlag.second = "";

    mPortIdFlag.first = false;
    mPortIdFlag.second = "";

    mCapFlag.first = false;
    mCapFlag.second = -1;

    mAddressFlag.first = false;
    mAddressFlag.second = {0, 0, 0, 0};
}

int sniffer::argCheck(int argc, char *argv[]){
    /* enum describing codes for argument types */
    const struct option longopts[] = {
            {"send-hello", no_argument, 0, 0},
            {"ttl", required_argument, 0, 0},
            {"duplex", required_argument, 0, 0},
            {"platform", required_argument, 0, 0},
            {"software-version", required_argument, 0, 0},
            {"device-id", required_argument, 0, 0},
            {"port-id", required_argument, 0, 0},
            {"capabilities", required_argument, 0, 0},
            {"address", required_argument, 0, 0},
            {0, 0, 0, 0}
    };

    int index;
    int arg = 0;

    while(-1 != (arg = getopt_long(argc, argv, "i:", longopts, &index))){
        switch(arg){

            case 'i':
                /* -i was already used */
                if(mInterfaceFlag.first){
                    return E_DUPLICITEARG;
                }
                mInterfaceFlag.first = true;
                std::cout << "Interface " << optarg <<std::endl;
                break;
            case 0:
                /* --send-hello */
                if(!strcmp(longopts[index].name, "send-hello")){
                    /* --send-hello was already used */
                    if(mHelloFlag){
                        return E_DUPLICITEARG;
                    }
                    mHelloFlag = true;
                    std::cout << "send-hello" << std::endl;
                    break;
                }
                /* for other flags must --send-hello must be set */
                if(mHelloFlag){
                    /* --ttl <time> */
                    if(!strcmp(longopts[index].name, "ttl")){
                        /* flag already used */
                        if(mTtlFlag.first){
                            return E_DUPLICITEARG;
                        }
                        mTtlFlag.first = true;
                        std::cout << "TTL: " << optarg << std::endl;
                        break;
                    }
                    if(!strcmp(longopts[index].name, "duplex")){
                        if(mDuplexFlag.first){
                            return E_DUPLICITEARG;
                        }
                        mDuplexFlag.first = true;
                        std::cout << "Duplex: " << optarg << std::endl;
                    }
                }
                break;
            default:
                return E_BADARG;
        }
    }

    /* Missing the only required argument, therefore I must quit the app */
    if(!mInterfaceFlag){
        return E_MISSINGREQUIREDARG;
    }

    return E_OK;
}