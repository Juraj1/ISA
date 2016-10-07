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

/****** other headers ******/
#include <unistd.h>



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
    std::pair<bool, char[4]>mAddressFlag;          /* --address */


public:
    /****** VARIABLES ******/


    /****** METHODS ******/
    /**
     * @param argc Argument count for parsing arguments
     * @param argv Vector of arguments for main program.
     */
    sniffer();

    /**
     * @brief Parses arguments.
     * @param argc Argument count for parsing arguments
     * @param argv Vector of arguments for main program.
     */
    int argCheck(int argc, char *argv[]);
    
};

#endif /* __SNIFFER_H__ */