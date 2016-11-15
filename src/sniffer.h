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
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include <string>
#include <vector>

/****** networking headers ******/
#include <sys/socket.h>     /* Core socket functions */
#include <netinet/in.h>     /* AF_INET family */
#include <netinet/tcp.h>    /* TCP headers */
#include <netinet/ether.h>  /* ethernet frames */
#include <sys/un.h>         /* PF_UNIX */
#include <arpa/inet.h>      /* Functions for IP addr manipulation */
#include <netdb.h>          /* Protocol name translation */
#include <net/if.h>         /* low level device control */
#include <sys/ioctl.h>      /* low level device control */
#include <net/ethernet.h>   /* L2 protocols */
#include <linux/if_packet.h>
#include <pcap.h>

/****** other headers ******/
#include <unistd.h>
#include <cctype>
#include <sys/utsname.h>    /* uname */
#include <sstream>          /* stringstream */

/* ethernet II header code */
#define ETHERNET_II 0x1
/* IEEE 802.3 ethernet header code */
#define ETHERNET_IEEE 0x2

/* LLDP type code */
#define LLDP_CODE 0x88cc

/* CDP type code */
#define CDP_CODE 0x2000

/* ethernet frame size */
#define ETHER_HEADER_SIZE 14


/* source for LLDP info: IEEE Std 802.1AB-2009 */

class sniffer{
private:
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

    typedef enum{
        portIdSubtype_reserved = 0,
        portIdSubtype_interfaceAlias,
        portIdSubtype_portComponent,
        portIdSubtype_macAddress,
        portIdSubtype_networkAddress,
        portIdSubtype_interfaceName,
        portIdSubtype_agentCircuitId,
        portIdSubtype_locallyAssigned
    }mPortIdSubtype_t;

    typedef enum{
        tlv_endOfLLDP = 0,
        tlv_chassisID,
        tlv_portID,
        tlv_TTL,
        tlv_portDescription,
        tlv_systemName,
        tlv_systemDescription,
        tlv_systemCapabilities,
        tlv_managementAddress,
    }mTlvType_t;

    typedef enum{
        chassisID_Reserved = 0,
        chassisID_ChassisComponent,
        chassisID_InterfaceAlias,
        chassisID_PortComponent,
        chassisID_MacAddress,
        chassisID_NetworkAddress,
        chassisID_InterfaceName,
        chassisID_LocallyAssigned
    }mChassisID_t;

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

    /**
     *
     */
    int mStartSniffing();

    /**
     *
     */
    std::string mExec(const char*);

    /**
     * @brief Callback method for pcap_loop.
     */
    static void mProcessPacket(u_char *, const struct pcap_pkthdr *, const u_char *);

    /**
     *
     */
    static int mParseLLDP(const u_char *);
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