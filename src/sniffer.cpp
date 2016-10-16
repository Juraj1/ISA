/****** my custom headers ******/
#include "sniffer.h"

#include <getopt.h>
#include <sstream>

/**
 * @file sniffer.cpp
 * @author Jiri Zahradnik <xzahra22>
 * @date 3rd October 2016
 * @brief Sniffer class implementation for ISA project.
 */

sniffer::sniffer() {
    /* we must set default uname, which can be later overwritten */
    mSetDefaultUname();

    mInterfaceFlag.first = false;
    mInterfaceFlag.second = "";

    mHelloFlag = false;

    mTtlFlag.first = false;
    mTtlFlag.second = 80;

    mDuplexFlag.first = false;
    mDuplexFlag.second = "";

    /* uname into mPlatformFlag */
    mSetDefaultPlatformFlag();

    /* uname -a into mVersionFlag */
    mSetDefaultVersionFlag();

    /* device flag */
    mSetDefaultDeviceIdFlag();

    mPortIdFlag.first = false;
    mPortIdFlag.second = "";

    mCapFlag.first = false;
    mCapFlag.second = -1;

    /* IP address init */
    mSetDefaultAddressFlag();
}

int sniffer::mStartSniffing(){
    /* open socket in promiscuous mode */

    return E_OK;
}

int sniffer::mSetIpAddress(){
    /*
     * code (c) ste, source: http://stackoverflow.com/questions/579783/how-to-detect-ip-address-change-programmatically-in-linux
     * modification and comments by me, Jiri Zahradnik <xzahra22>
     */
    /* socket */
    int s;

    /* struct to hold information about interface */
    struct ifreq ifr = {};

    /* protocol family, not address family, therefore PF_INET instead of AF_INET */
    s = socket(PF_INET, SOCK_DGRAM, 0);

    /* copy name of the interface */
    strncpy(ifr.ifr_name, mInterfaceFlag.second.c_str(), sizeof(ifr.ifr_name));

    /* syscall to get info about interface */
    if(0 <= ioctl(s, SIOCGIFADDR, &ifr)){
        /* store IP address */
        mAddressFlag.second.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    } else {
        shutdown(s, 2);
        return E_UNKNOWN;
    }

    /* I successfuly set the IP address */
    shutdown(s, 2);
    return E_OK;
}

/* exec method (c) waqas from http://stackoverflow.com/questions/478898/how-to-execute-a-command-and-get-output-of-command-within-c-using-posix */
std::string sniffer::mExec(const char* cmd) {
    char buffer[512];
    std::string result = "";
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

void sniffer::mSetDefaultAddressFlag(){
    mAddressFlag.first = false;
    inet_pton(AF_INET, "...", &(mAddressFlag.second));
}

void sniffer::mSetDefaultDeviceIdFlag(){
    mDeviceIdFlag.first = false;
    /* set default hostname */
    char hostname[2048];
    gethostname(hostname, 2048);
    mDeviceIdFlag.second = hostname;
}

void sniffer::mSetDefaultPlatformFlag(){
    mPlatformFlag.first = false;
    mPlatformFlag.second = mSysInfo.sysname;
}

void sniffer::mSetDefaultVersionFlag(){
    /* stringstream where I will be putting parts of uname */
    std::stringstream str;
    str << mSysInfo.sysname << " ";
    str << mSysInfo.nodename << " ";
    str << mSysInfo.release << " ";
    str << mSysInfo.version << " ";
    str << mSysInfo.machine << " ";
    str << mSysInfo.domainname;

    mVersionFlag.first = false;
}

void sniffer::mSetDefaultUname(){
    uname(&mSysInfo);
    mVersionFlag.second = mExec("uname -a");
}

bool sniffer::mIsNumber(char *str){
    char len = strlen(str);
    for(int i = 0; i < len; i++){
        if(!isdigit(str[i])){
            return false;
        }
    }
    return true;
}

int sniffer::mArgCheck(int argc, char *argv[]){
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
                mInterfaceFlag.second = optarg;

                /* set default value for --port-id */
                mPortIdFlag.second = optarg;

                /* set default IP address for said interface */
                if(E_UNKNOWN == mSetIpAddress()){
                    return E_UNKNOWN;
                }

                std::cout << "Interface: " << optarg <<std::endl;
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
                        if(!mIsNumber(optarg)){
                            return E_EXPECTEDINTASARGUMENT;
                        }
                        mTtlFlag.second = atoi(optarg);
                        std::cout << "TTL: " << optarg << std::endl;
                        break;
                    }
                    /* --duplex */
                    if(!strcmp(longopts[index].name, "duplex")){
                        /* flag already used */
                        if(mDuplexFlag.first){
                            return E_DUPLICITEARG;
                        }
                        /* some random gibberish as the argument */
                        if(strcmp(optarg, "half") && strcmp(optarg, "full")){
                            return E_BADARG;
                        }

                        mDuplexFlag.first = true;
                        mDuplexFlag.second = optarg;
                        std::cout << "Duplex: " << optarg << std::endl;
                        break;
                    }
                    /* --platform */
                    if(!strcmp(longopts[index].name, "platform")){
                        /* flag already used */
                        if(mPlatformFlag.first){
                            return E_DUPLICITEARG;
                        }

                        mPlatformFlag.first = true;
                        mPlatformFlag.second = optarg;
                        std::cout << "Platform: " << optarg << std::endl;
                        break;
                    }
                    /* --software-version */
                    if(!strcmp(longopts[index].name, "software-version")){
                        /* flag already used */
                        if(mVersionFlag.first){
                            return E_DUPLICITEARG;
                        }

                        mVersionFlag.first = true;
                        mVersionFlag.second = optarg;
                        std::cout << "Version: " << optarg << std::endl;
                        break;
                    }
                    /* --device-id */
                    if(!strcmp(longopts[index].name, "device-id")){
                        /* flag already used */
                        if(mDeviceIdFlag.first){
                            return E_DUPLICITEARG;
                        }

                        mDeviceIdFlag.first = true;
                        mDeviceIdFlag.second = optarg;
                        std::cout << "Device-ID: " << mDeviceIdFlag.second << std::endl;
                        break;
                    }
                    /* --port-id */
                    if(!strcmp(longopts[index].name, "port-id")){
                        /* flag already used */
                        if(mPortIdFlag.first){
                            return E_DUPLICITEARG;
                        }

                        mPortIdFlag.first = true;
                        mPortIdFlag.second = optarg;
                        std::cout << "Port-ID: " << optarg << std::endl;
                    }
                    /* --capabilities */
                    if(!strcmp(longopts[index].name, "capabilities")){
                        /* flag already used */
                        if(mCapFlag.first){
                            return E_DUPLICITEARG;
                        }
                        /* check for validity of integer */
                        if(!mIsNumber(optarg)){
                            return E_EXPECTEDINTASARGUMENT;
                        }

                        mCapFlag.first = true;
                        mCapFlag.second = atoi(optarg);
                        std::cout << "Capabilities: " << optarg << std::endl;
                        break;
                    }
                    /* --address */
                    if(!strcmp(longopts[index].name, "address")){
                        /* flag already used */
                        if(mAddressFlag.first){
                            return E_DUPLICITEARG;
                        }

                        mAddressFlag.first = true;
                        /* parse IPv4 address from string, if not an valid IPv4 address, return bad arg */
                        if(!inet_pton(AF_INET, optarg, &(mAddressFlag.second.sin_addr))){
                            return E_BADARG;
                        }
                    }
                } else {
                    return E_BADARG;
                }
                break;
            default:
                return E_BADARG;
        }
    }

    std::cout << "******DEBUG******" << std::endl;
    std::cout << mInterfaceFlag.second << std::endl;
    std::cout << mPlatformFlag.second << std::endl;
    std::cout << mVersionFlag.second;
    std::cout << mDeviceIdFlag.second << std::endl;
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &mAddressFlag.second.sin_addr, str, INET_ADDRSTRLEN);
    std::cout << str << std::endl;
    std::cout << "******DEBUG******" << std::endl;

    /* Missing the only required argument, therefore I must quit the app */
    if(!mInterfaceFlag.first){
        return E_MISSINGREQUIREDARG;
    }

    return E_OK;
}