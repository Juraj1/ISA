/**
 * @file sniffer.h
 * @author Jiri Zahradnik <xzahra22>
 * @date 3rd October 2016
 * @brief Class definition for ISA project.
 */

/* include protection */
#ifndef __SNIFFER_H__
#define __SNIFFER_H__

/****** custom headers ******/
#include "error.h"


/****** standard headers ******/
#include <cstdlib>

/****** networking headers ******/
#include <sys/socket.h>     /* Core socket functions */
#include <netinet/in.h>     /* AF_INET family */
#include <netinet/tcp.h>    /* TCP headers */
#include <sys/un.h>         /* PF_UNIX */
#include <arpa/inet.h>      /* Functions for IP addr manipulation */
#include <netdb.h>          /* Protocol name translation */
#include <net/if.h>         /* low level device control */
#include <sys/ioctl.h>      /* low level device control */

/****** other headers ******/
#include <unistd.h>
#include <cctype>
#include <sys/utsname.h>    /* uname */
#include <sstream>          /* stringstream */



class sniffer{
protected:
    /* argument flags */
    std::pair<bool, std::string>mInterfaceFlag;    /* -i */
    bool mHelloFlag;                               /* --send-hello */
    std::pair<bool, int>mTtlFlag;                  /* --ttl */
    std::pair<bool, std::string>mDuplexFlag;       /* --duplex */
    std::pair<bool, std::string>mPlatformFlag;     /* --platform */
    std::pair<bool, std::string>mVersionFlag;      /* --software-version */
    std::pair<bool, std::string>mDeviceIdFlag;     /* --device-id */
    std::pair<bool, std::string>mPortIdFlag;       /* --port-id */
    std::pair<bool, int>mCapFlag;                  /* --capabilities */
    std::pair<bool, struct sockaddr_in>mAddressFlag;          /* --address */

    /* uname struct */
    struct utsname mSysInfo;

    /****** METHODS ******/
    /**
     * @brief Checks whether string is a number.
     * @param String to be checked.
     * @return True if string is number.
     */
    bool mIsNumber(char *);

    /**
     * @brief Sets Uname default uname;
     */
    void mSetDefaultUname();

    /**
     * @brief Sets default uname -a + arg flag.
     */
    void mSetDefaultVersionFlag();

    /**
     * @brief Sets default uname + arg flag.
     */
    void mSetDefaultPlatformFlag();

    /**
     * @brief Sets default hostname + arg flag.
     */
    void mSetDefaultDeviceIdFlag();

    /**
     * @brief Sets default address flag;
     */
    void mSetDefaultAddressFlag();

    /**
     * @brief Sets ip address of an interface.
     */
    int mSetIpAddress();

public:
    /****** VARIABLES ******/


    /****** METHODS ******/
    /**
     * @brief Constructor of class sniffer to set default values.
     */
    sniffer();

    /**
     * @brief Parses arguments.
     * @param argc Argument count for parsing arguments.
     * @param argv Vector of arguments for main program.
     */
    int mArgCheck(int, char **);
};

#endif /* __SNIFFER_H__ */