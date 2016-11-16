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

int sniffer::mParseLLDP(const u_char *packet) {
    u_char *packetPointer = (u_char *)packet;

    /* | Chasis TLV | Port ID TLV | TTL TLV | OPTIONAL TLVs | End of LLDPDU TLV | */

    /*
     * TLV FORMAT:
     * | 7 bit TYPE | 9 bit LENGTH | N Octets of data |
     */

    std::cout << "LLDP contains: " << std::endl;
    uint16_t dataLen = 0;
    uint16_t tlvType = 0;
    char *data = NULL;

    for (int i = 1; ; i++) {
        /* read TLV header and move pointer */
        memcpy(&dataLen, packetPointer, 2);
        packetPointer += 2;
        dataLen = ntohs(dataLen);

        /* get TLV Type */
        tlvType = dataLen;
        tlvType >>= 9;

        /* clear top 7 bits to get chasis data length */
        dataLen &= 0x01FF;

        switch(tlvType) {
            /* end of LLDP packet */
            case tlv_endOfLLDP: {
                return 0;
            }
            case tlv_chassisID: {
                /* read chassis id subtype and move pointer to another byte */
                uint8_t idSubtype;
                memcpy(&idSubtype, packetPointer++, 1);
                dataLen--;
                std::string idType = "";

                data = (char *) malloc(dataLen * sizeof(char));
                switch (idSubtype) {
                    case chassisID_Reserved: {
                        idType = "Reserved";
                        break;
                    }
                    case chassisID_ChassisComponent: {
                        idType = "Chassis component";

                        std::vector<char> stringVector;
                        for (int j = 0; j < dataLen; j++) {
                            /* read byte and move through paket to next index */
                            stringVector.push_back(data[i]);
                            packetPointer++;
                            dataLen--;
                        }
                        stringVector.push_back(0);
                        std::string str(stringVector.begin(), stringVector.end());

                        std::cout << "TLV Type: Chassis ID - " << idType << " | " << "data: " << str << std::endl;
                        break;
                    }
                    case chassisID_InterfaceAlias: {
                        idType = "Interface alias";
                        std::vector<char> stringVector;
                        for (int j = 0; j < dataLen; j++) {
                            /* read byte and move through paket to next index */
                            stringVector.push_back(data[i]);
                            packetPointer++;
                            dataLen--;
                        }
                        stringVector.push_back(0);
                        std::string str(stringVector.begin(), stringVector.end());

                        std::cout << "TLV Type: Chassis ID - " << idType << " | " << "data: " << str << std::endl;
                        break;
                    }
                    case chassisID_PortComponent: {
                        idType = "Port component";
                        std::vector<char> stringVector;
                        for (int j = 0; j < dataLen; j++) {
                            /* read byte and move through paket to next index */
                            stringVector.push_back(data[i]);
                            packetPointer++;
                            dataLen--;
                        }
                        stringVector.push_back(0);
                        std::string str(stringVector.begin(), stringVector.end());

                        std::cout << "TLV Type: Chassis ID - " << idType << " | " << "data: " << str << std::endl;
                        break;
                    }
                    case chassisID_MacAddress: {
                        idType = "MAC address";
                        struct ether_header *head = (struct ether_header *) malloc(sizeof(struct ether_header));
                        /* get MAC address and move pointer */
                        memcpy(&(head->ether_dhost), packetPointer, 6);
                        packetPointer += 6;
                        dataLen -= 6;

                        std::cout << "TLV Type: Chassis ID - " << idType << " | " << "data: "
                                  << ether_ntoa((struct ether_addr *) head->ether_dhost) << std::endl;
                        free(head);
                        break;
                    }
                    case chassisID_NetworkAddress: {
                        idType = "Network address";
                        /* get address family and move pointer */
                        uint8_t addressFamily;
                        memcpy(&addressFamily, packetPointer++, 1);
                        dataLen--;
                        std::string str = "";
                        switch (addressFamily) {
                            case 0: {
                                str = "Reserved";
                                std::cout << "TLV Type: Chassis ID - " << idType << " | " << "IANA AFN: "
                                          << addressFamily << " = " << str << std::endl;
                                break;
                            }
                            case 1: {
                                str = "IPv4";
                                struct in_addr *addr = (struct in_addr *) malloc(sizeof(struct in_addr));

                                /* copy IP from packet to memory and move packetPointer */
                                memcpy(addr, packetPointer, 4);
                                packetPointer += 4;
                                dataLen -= 4;

                                /* get address to string */
                                char ipv4addr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, addr, ipv4addr, INET_ADDRSTRLEN);

                                std::cout << "TLV Type: Chassis ID - " << idType << " | " << "IANA AFN: "
                                          << addressFamily << " = " << str
                                          << "Address: " << ipv4addr << std::endl;

                                free(addr);
                                break;
                            }
                            case 2: {
                                str = "IPv6";
                                std::cout << "TLV Type: Chassis ID - " << idType << " | " << "IANA AFN: "
                                          << addressFamily << " = " << str << std::endl;
                                packetPointer += dataLen;
                                dataLen = 0;
                                break;
                            }
                            default: {
                                str = "Some other address type";
                                std::cout << "TLV Type: Chassis ID - " << idType << " | " << "IANA AFN: "
                                          << addressFamily << " = " << str << std::endl;
                                packetPointer += dataLen;
                                dataLen = 0;
                            }
                        }
                        break;
                    }
                    case chassisID_InterfaceName: {
                        idType = "Interface name";
                        std::vector<char> stringVector;
                        for (int j = 0; j < dataLen; j++) {
                            /* read byte and move through paket to next index */
                            stringVector.push_back(data[i]);
                            packetPointer++;
                            dataLen--;
                        }
                        stringVector.push_back(0);
                        std::string str(stringVector.begin(), stringVector.end());

                        std::cout << "TLV Type: Chassis ID - " << idType << " | " << "data: " << str << std::endl;
                        break;
                    }
                    case chassisID_LocallyAssigned: {
                        idType = "Locally assigned";
                        std::vector<char> stringVector;
                        for (int j = 0; j < dataLen; j++) {
                            /* read byte and move through paket to next index */
                            stringVector.push_back(data[i]);
                            packetPointer++;
                            dataLen--;
                        }
                        stringVector.push_back(0);
                        std::string str(stringVector.begin(), stringVector.end());

                        std::cout << "TLV Type: Chassis ID - " << idType << " | " << "data: " << str << std::endl;
                        break;
                    }
                    default:
                        idType = "Reserved";
                        packetPointer += dataLen;
                        dataLen = 0;
                }

                free(data);
                break;
            }
            case tlv_portID: {
                /* get portID subtype and move packet pointer */
                uint8_t IDsubtype;
                memcpy(&IDsubtype, packetPointer++, 1);
                dataLen--;

                /* ID subtype basis */
                std::string str = "";
                char *subtypeData = (char *) malloc(dataLen * sizeof(char));// + sizeof(char));
                bzero(subtypeData, dataLen + 1);
                switch (IDsubtype) {
                    case portIdSubtype_reserved: {
                        str = "Reserved";
                        std::cout << "TLV Type: PortID ID - " << str << std::endl;
                        packetPointer += dataLen;
                        dataLen = 0;

                        break;
                    }
                    case portIdSubtype_interfaceAlias: {
                        str = "Interface alias";
                        /* get the rest of TLV body */
                        memcpy(subtypeData, packetPointer, dataLen);
                        packetPointer += dataLen;
                        dataLen = 0;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: " << subtypeData << std::endl;
                        break;
                    }
                    case portIdSubtype_portComponent: {
                        str = "Port component";
                        /* get the rest of TLV body */
                        memcpy(subtypeData, packetPointer, dataLen);
                        packetPointer += dataLen;
                        dataLen = 0;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: " << subtypeData << std::endl;
                        break;
                    }
                    case portIdSubtype_macAddress: {
                        str = "MAC address";
                        struct ether_header *head = (struct ether_header *) malloc(sizeof(struct ether_header));
                        /* get MAC address and move pointer */
                        memcpy(&(head->ether_dhost), packetPointer, 6);
                        packetPointer += 6;
                        dataLen -= 6;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: "
                                  << ether_ntoa((struct ether_addr *) head->ether_dhost) << std::endl;

                        free(head);
                        break;
                    }
                    case portIdSubtype_networkAddress: {
                        str = "Network address";
                        /* get address family and move pointer */
                        uint8_t addressFamily;
                        memcpy(&addressFamily, packetPointer++, 1);
                        dataLen--;

                        std::string strA = "";
                        switch (addressFamily) {
                            case 0: {
                                strA = "Reserved";
                                packetPointer += dataLen;
                                dataLen = 0;

                                std::cout << "TLV Type: PortID ID - " << str << " | " << "IANA AFN: " << addressFamily
                                          << " = " << strA << std::endl;
                                break;
                            }
                            case 1: {
                                strA = "IPv4";
                                struct in_addr *addr = (struct in_addr *) malloc(sizeof(struct in_addr));

                                /* copy IP from packet to memory and move packetPointer */
                                memcpy(addr, packetPointer, 4);
                                packetPointer += 4;
                                dataLen -= 4;

                                /* get address to string */
                                char ipv4addr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, addr, ipv4addr, INET_ADDRSTRLEN);

                                std::cout << "TLV Type: PortID ID - " << str << " | " << "IANA AFN: " << addressFamily
                                          << " = " << strA
                                          << "Address: " << ipv4addr << std::endl;

                                free(addr);
                                break;
                            }
                            case 2: {
                                strA = "IPv6";
                                std::cout << "TLV Type: PortID ID - " << str << " | " << "IANA AFN: " << addressFamily
                                          << " = " << strA << std::endl;
                                packetPointer += dataLen;
                                dataLen = 0;
                                break;
                            }
                            default: {
                                strA = "Some other address type";
                                std::cout << "TLV Type: PortID ID - " << str << " | " << "IANA AFN: " << addressFamily
                                          << " = " << strA << std::endl;
                                packetPointer += dataLen;
                                dataLen = 0;
                            }
                        }
                        break;
                    }
                    case portIdSubtype_interfaceName: {
                        str = "Interface name";
                        /* get the rest of TLV body */
                        memcpy(subtypeData, packetPointer, dataLen);
                        packetPointer += dataLen;
                        dataLen = 0;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: " << subtypeData << std::endl;
                        break;
                    }
                    case portIdSubtype_agentCircuitId: {
                        str = "Agent circuit ID";
                        /* get the rest of TLV body */
                        memcpy(subtypeData, packetPointer, dataLen);
                        packetPointer += dataLen;
                        dataLen = 0;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: " << subtypeData << std::endl;
                        break;
                    }
                    case portIdSubtype_locallyAssigned: {
                        str = "Locally assigned";
                        /* get the rest of TLV body */
                        memcpy(subtypeData, packetPointer, dataLen);
                        packetPointer += dataLen;
                        dataLen = 0;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: " << subtypeData << std::endl;
                        break;
                    }
                    default: {
                        str = "Reserved";
                        memcpy(subtypeData, packetPointer, dataLen);
                        packetPointer += dataLen;
                        dataLen = 0;

                        std::cout << "TLV Type: PortID ID - " << str << " | " << "data: " << subtypeData << std::endl;
                    }
                }
                free(subtypeData);
                break;
            }
            case tlv_TTL: {
                /* get TTL and move pointer */
                uint16_t timeToLive;
                memcpy(&timeToLive, packetPointer, dataLen);
                timeToLive = ntohs(timeToLive);
                packetPointer += dataLen;
                dataLen = 0;

                std::cout << "TLV Type: TTL - " << "Time To Live" << " | " << "data: " << std::dec << timeToLive
                          << std::endl;
                break;
            }
            case tlv_portDescription: {
                /* get data from TLV and move pointer */
                char *description = (char *) malloc(dataLen * sizeof(char));// + sizeof(char));
                bzero(description, dataLen + 1);

                memcpy(description, packetPointer, dataLen);
                packetPointer += dataLen;
                dataLen = 0;
                std::cout << "TLV Type: Port description" << " | " << "data: " << description << std::endl;

                free(description);
                break;
            }
            case tlv_systemName: {
                /* get data from TLV and move pointer */
                char *description = (char *) malloc(dataLen * sizeof(char));// + sizeof(char));
                bzero(description, dataLen + 1);

                memcpy(description, packetPointer, dataLen);
                packetPointer += dataLen;
                dataLen = 0;
                std::cout << "TLV Type: System name" << " | " << "data: " << description << std::endl;

                free(description);
                break;
            }
            case tlv_systemDescription: {
                /* get data from TLV and move pointer */
                char *description = (char *) malloc(dataLen * sizeof(char));// + sizeof(char));
                bzero(description, dataLen + 1);

                memcpy(description, packetPointer, dataLen);
                packetPointer += dataLen;
                dataLen = 0;
                std::cout << "TLV Type: System description " << " | " << "data: " << description << std::endl;

                free(description);
                break;
            }
            case tlv_systemCapabilities: {
                uint16_t sysCap = 0;
                uint16_t enabledCap = 0;

                /* load system capabilities */
                memcpy(&sysCap, packetPointer, 2);
                sysCap = ntohs(sysCap);
                packetPointer += 2;
                dataLen -= 2;

                /* load enabled capabilities */
                memcpy(&enabledCap, packetPointer, 2);
                enabledCap = ntohs(enabledCap);
                packetPointer += 2;
                dataLen -= 2;

                std::cout << "TLV Type: System Capabilities" << std::endl;
                std::cout << "          System supported capabilities: ";
                if (sysCap & CAP_STATION_ONLY) {
                    std::cout << "Station only; ";

                    if (sysCap ^ CAP_STATION_ONLY) {
                        std::cout << "Packet TLV corrupted(not compliant with standard), discarting" << std::endl;
                        return 0;
                    }
                }
                if (sysCap & CAP_OTHER) {
                    std::cout << "Other; ";
                }
                if (sysCap & CAP_REPEATER) {
                    std::cout << "Repeater; ";
                }
                if (sysCap & CAP_MAC_BRIDGE) {
                    std::cout << "MAC Bridge; ";
                }
                if (sysCap & CAP_WLAN_ACC_POINT) {
                    std::cout << "WLAN Access Point; ";
                }
                if (sysCap & CAP_ROUTER) {
                    std::cout << "Router; ";
                }
                if (sysCap & CAP_TELEPHONE) {
                    std::cout << "Telephone; ";
                }
                if (sysCap & CAP_DOCSIS_CABLE_DEVICE) {
                    std::cout << "DOCSIS cable device; ";
                }
                if (sysCap & CAP_C_VLAN_VLAN_BRIDGE) {
                    std::cout << "C-VLAN Component of a VLAN Bridge; ";
                }
                if (sysCap & CAP_S_VLAN_VLAN_BRIDGE) {
                    std::cout << "S-VLAN Component of a VLAN Bridge; ";
                }
                if (sysCap & CAP_TWO_PORT_MAC_RELAY) {
                    std::cout << "Two-Port MAC Relay";
                }
                std::cout << std::endl;

                std::cout << "          System enabled capabilities: ";
                if (enabledCap & CAP_STATION_ONLY) {
                    std::cout << "Station only; ";

                    if (enabledCap ^ CAP_STATION_ONLY) {
                        std::cout << "Packet TLV corrupted(not compliant with standard), discarting" << std::endl;
                        return 0;
                    }
                }
                if (enabledCap & CAP_OTHER) {
                    std::cout << "Other; ";
                }
                if (enabledCap & CAP_REPEATER) {
                    std::cout << "Repeater; ";
                }
                if (enabledCap & CAP_MAC_BRIDGE) {
                    std::cout << "MAC Bridge; ";
                }
                if (enabledCap & CAP_WLAN_ACC_POINT) {
                    std::cout << "WLAN Access Point; ";
                }
                if (enabledCap & CAP_ROUTER) {
                    std::cout << "Router; ";
                }
                if (enabledCap & CAP_TELEPHONE) {
                    std::cout << "Telephone; ";
                }
                if (enabledCap & CAP_DOCSIS_CABLE_DEVICE) {
                    std::cout << "DOCSIS cable device; ";
                }
                if (enabledCap & CAP_C_VLAN_VLAN_BRIDGE) {
                    std::cout << "C-VLAN Component of a VLAN Bridge; ";
                }
                if (enabledCap & CAP_S_VLAN_VLAN_BRIDGE) {
                    std::cout << "S-VLAN Component of a VLAN Bridge; ";
                }
                if (enabledCap & CAP_TWO_PORT_MAC_RELAY) {
                    std::cout << "Two-Port MAC Relay";
                }
                std::cout << std::endl;

                break;
            }
            case tlv_managementAddress: {
                std::cout << "TLV Type: Management Address | ";
                /* get management string length and move packet pointer */
                uint16_t managementAddrStrLen = 0;
                memcpy(&managementAddrStrLen, packetPointer++, 1);
                /* TODO fix parsovani pameti */
                std::cout << "Length of TLV: " << dataLen << " | " << "Address string length: " << std::hex
                          << managementAddrStrLen << " | " << std::endl;
                dataLen--;

                /* get management addres subtype */
                uint8_t managementAddrSubtype;
                memcpy(&managementAddrSubtype, packetPointer++, 1);
                dataLen--;

                switch (managementAddrSubtype) {
                    case 1: {
                        std::cout << "          Subtype: IPv4" << " | ";
                        struct in_addr *addr = (struct in_addr *) malloc(sizeof(struct in_addr));

                        /* copy IP from packet to memory and move packetPointer */
                        memcpy(addr, packetPointer, 4);
                        packetPointer += 4;
                        dataLen -= 4;

                        /* get address to string */
                        char ipv4addr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, addr, ipv4addr, INET_ADDRSTRLEN);

                        std::cout << "IPv4 Addr: " << ipv4addr << std::endl;

                        free(addr);
                        break;
                    }
                    default: {
                        std::cout << "Subtype: Definitely not IPv4" << std::endl;
                        packetPointer += managementAddrStrLen;
                        dataLen -= managementAddrStrLen;
                    }
                }

                /*get interface numbering subtype */
                uint16_t interfaceNumberingSubtype = 0;
                memcpy(&interfaceNumberingSubtype, packetPointer++, 1);
                dataLen--;

                std::cout << "          Interface numbering subtype: " << interfaceNumberingSubtype << std::endl;

                /* get 4 bytes of interface number */
                uint32_t interfaceNumber;
                memcpy(&interfaceNumber, packetPointer, 4);
                interfaceNumber = ntohl(interfaceNumber);
                packetPointer += 4;
                dataLen -= 4;

                std::cout << "          Interface number: " << std::hex << interfaceNumber << std::endl;

                /* OID string length */
                uint8_t oidStrlen = 0;
                memcpy(&oidStrlen, packetPointer++, 1);
                dataLen--;
                /* if we got any data left */
                if (dataLen) {
                    char *objectIdentifier = (char *) malloc(dataLen * sizeof(char) + sizeof(char));
                    bzero(objectIdentifier, dataLen + 1);
                    std::cout << "          OID String: " << objectIdentifier << std::endl;
                }
                break;
            }
            case tlv_organizationallySpecific:{
                std::cout << "Organizationally specific TLV with LLDPDU of size: " << std::dec << dataLen << std::endl;
                packetPointer += dataLen;
                dataLen = 0;
                break;
            }
            default: {
                std::cout << "Reserved TLV" << std::endl;
                packetPointer += dataLen;
                dataLen = 0;
                break;
            }
        }
    }

    return 0;
}

int sniffer::mParseCDP(const u_char *packet, const uint16_t packetLength){

    u_char *packetPointer = (u_char *)packet;
    /* get version */
    uint8_t version = 0;
    memcpy(&version, packetPointer++, 1);

    uint8_t  TTL = 0;
    memcpy(&TTL, packetPointer++, 1);

    uint16_t checksum;
    memcpy(&checksum, packetPointer, 2);
    packetPointer += 2;
    checksum = ntohs(checksum);

    std::cout << "CDP contains:" << std::endl;
    std::cout << "CDP Version: " << (int)version << " | " << "Time to live: " << std::dec << (int)TTL << " | " << "Checksum: 0x" << std::hex << checksum << std::endl;

    /* remaining packet length = total length - header */
    uint16_t remainingPacketLenght = packetLength - 4;

    /* iterating untill I am at the end of CDP payload */
    while(0 < remainingPacketLenght){
        /* get TLV type and move */
        uint16_t type;
        memcpy(&type, packetPointer, 2);
        type = ntohs(type);
        packetPointer += 2;
        remainingPacketLenght -= 2;

        /* get TLV len, from that get Value field length and move */
        uint16_t dataLen;
        mempcpy(&dataLen, packetPointer, 2);
        dataLen = ntohs(dataLen);
        dataLen -= 4;

        packetPointer += 2;
        remainingPacketLenght -= 2;
        switch(type){
            case mCiscoTlvType_deviceID:{
                char *ID = (char *)malloc(dataLen * sizeof(char) + sizeof(char));
                bzero(ID, dataLen * sizeof(char) + sizeof(char));
                memcpy(ID, packetPointer, dataLen);
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;

                std::cout << "TLV Type: Device-ID | ID: " << ID << std::endl;

                free(ID);
                break;
            }
            case mCiscoTlvType_address:{

                std::cout << "TLV Type: Address" << std::endl;

                uint32_t addrCount;
                memcpy(&addrCount, packetPointer, 4);
                addrCount = ntohl(addrCount);
                packetPointer += 4;
                remainingPacketLenght -= 4;
                dataLen -= 4;

                std::cout << "          AddressCount: " << addrCount << std::endl;

                uint8_t protocolType;
                memcpy(&protocolType, packetPointer++, 1);
                remainingPacketLenght--;
                dataLen--;

                uint8_t protocolLength;
                memcpy(&protocolLength, packetPointer++, 1);
                remainingPacketLenght--;
                dataLen--;

                switch(protocolType){
                    case 1:{
                        std::cout << "          Protocol Type: NLPID format" << " | ";

                        /* therefore only 1 byte for protocol, after operation, shift */
                        uint8_t protocol;
                        memcpy(&protocol, packetPointer++, 1);
                        remainingPacketLenght--;
                        dataLen--;

                        switch(protocol){
                            case 0x81:{
                                std::cout << "Protocol: ISO CLNS" << std::endl;
                                break;
                            }
                            case 0xCC:{
                                std::cout << "Protocol: IP" << " | ";

                                uint16_t addrLen;
                                memcpy(&addrLen, packetPointer, 2);
                                addrLen = ntohs(addrLen);
                                packetPointer += 2;
                                remainingPacketLenght -= 2;
                                dataLen -= 2;

                                struct in_addr *addr = (struct in_addr *) malloc(sizeof(struct in_addr));

                                /* copy IP from packet to memory and move packetPointer */
                                memcpy(addr, packetPointer, 4);
                                packetPointer += 4;
                                remainingPacketLenght -= 4;
                                dataLen -= 4;

                                /* get address to string */
                                char ipv4addr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, addr, ipv4addr, INET_ADDRSTRLEN);

                                std::cout << "IP Address: " << ipv4addr;

                                free(addr);
                                break;
                            }
                        }
                        break;
                    }
                    case 2:{
                        std::cout << "          Protocol Type: 802.2 format" << " | ";
                        uint64_t protocol;
                        memcpy(&protocol, packetPointer, 8);
                        /* get to format "normal people" use */
                        protocol = htobe64(protocol);
                        packetPointer += 8;
                        remainingPacketLenght -= 8;
                        dataLen -= 8;

                        std::cout << "Protocol code: 0x" << std::hex << protocol;

                        break;
                    }
                    default:{
                        std::cout << "          Protocol Type: Unknown" << " | " ;
                    }

                }

                std::cout << std::endl;

                /* get the rest of TLV data */
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;
                break;
            }
            case mCiscoTlvType_portID:{
                char *ID = (char *)malloc(dataLen * sizeof(char) + sizeof(char));
                bzero(ID, dataLen * sizeof(char) + sizeof(char));
                memcpy(ID, packetPointer, dataLen);
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;

                std::cout << "TLV Type: port-ID | ID: " << ID << std::endl;

                free(ID);
                break;
            }
            case mCiscoTlvType_capabilities:{
                std::cout << "TLV Type: Capabilities" << std::endl;
                uint32_t caps;
                memcpy(&caps, packetPointer, dataLen);
                caps = htonl(caps);

                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;

                std::cout << "          ";
                if(caps & CDP_CAP_ROUTER){
                    std::cout << "Router: Yes";
                } else {
                    std::cout << "Router: No";
                }

                std::cout << std::endl << "          ";
                if(caps & CDP_CAP_TRANSPARENT_BRIDGE){
                    std::cout << "Transparent Bridge: Yes";
                } else {
                    std::cout << "Transparent Bridge: No";
                }

                std::cout << std::endl << "          ";
                if(caps & CDP_CAP_SOURCE_ROUTE_BRIDGE){
                    std::cout << "Source Route Bridge: Yes";
                } else {
                    std::cout << "Source Route Bridge: No";
                }

                std::cout << std::endl << "          ";
                if(caps & CDP_CAP_SWITCH){
                    std::cout << "Switch: Yes";
                } else {
                    std::cout << "Switch: No";
                }

                std::cout << std::endl << "          ";
                if(caps & CDP_CAP_HOST){
                    std::cout << "Host: Yes";
                } else {
                    std::cout << "Host: No";
                }

                std::cout << std::endl << "          ";
                if(caps & CDP_CAP_IGMP_CAPABLE){
                    std::cout << "IGMP Capable: Yes";
                } else {
                    std::cout << "IGMP Capable: No";
                }

                std::cout << std::endl << "          ";
                if(caps & CDP_CAP_REPEATER){
                    std::cout << "Repeater: Yes";
                } else {
                    std::cout << "Repeater: No";
                }

                std::cout << std::endl;
                break;
            }
            case mCiscoTlvType_version:{
                char *ID = (char *)malloc(dataLen * sizeof(char) + sizeof(char));
                bzero(ID, dataLen * sizeof(char) + sizeof(char));
                memcpy(ID, packetPointer, dataLen);
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;

                std::cout << "TLV Type: Version | ID: " << ID << std::endl;

                free(ID);
                break;
            }
            case mCiscoTlvType_platform:{
                char *ID = (char *)malloc(dataLen * sizeof(char) + sizeof(char));
                bzero(ID, dataLen * sizeof(char) + sizeof(char));
                memcpy(ID, packetPointer, dataLen);
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;

                std::cout << "TLV Type: Platform | ID: " << ID << std::endl;

                free(ID);
                break;
            }
            case mCiscoTlvType_ipNetworkPrefix:{
                std::cout << "TLV Type: IP Prefixes" << std::endl;
                /* no IP prefixes */
                if(0 == dataLen){
                    break;
                }

                /* 5 bytes for each address */
                uint16_t addCount = dataLen / 5;

                for(int i = 0; i < addCount; i++){
                    struct in_addr *addr = (struct in_addr *) malloc(sizeof(struct in_addr));

                    /* copy IP from packet to memory and move packetPointer */
                    memcpy(addr, packetPointer, 4);
                    packetPointer += 4;
                    remainingPacketLenght -= 4;
                    dataLen -= 4;

                    uint8_t prefix;
                    memcpy(&prefix, packetPointer++, 1);
                    remainingPacketLenght--;
                    dataLen--;


                    /* get address to string */
                    char ipv4addr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, addr, ipv4addr, INET_ADDRSTRLEN);

                    std::cout << "          IP Prefix: " << ipv4addr << "/" << std::dec << (int)prefix << std::endl;

                    free(addr);
                }

                /* alignment */
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;
                break;
            }
            case mCiscoTlvType_vtpManagementDomain:{
                char *ID = (char *)malloc(dataLen * sizeof(char) + sizeof(char));
                bzero(ID, dataLen * sizeof(char) + sizeof(char));
                memcpy(ID, packetPointer, dataLen);
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;

                std::cout << "TLV Type: VTP Management Domain | ID: " << ID << std::endl;

                free(ID);
                break;
            }
            case mCiscoTlvType_duplex:{
                std::cout << "TLV Type: Duplex => ";
                uint8_t duplex;
                memcpy(&duplex, packetPointer++, 1);
                remainingPacketLenght--;
                dataLen--;

                if(0 == duplex){
                    std::cout << "Half" << std::endl;
                } else {
                    std::cout << "Full" << std::endl;
                }
                break;
            }
            case mCiscoTlvType_managementAddresses:{
                std::cout << "TLV Type: Management Addresses" << std::endl;

                uint32_t addrCount;
                memcpy(&addrCount, packetPointer, 4);
                addrCount = ntohl(addrCount);
                packetPointer += 4;
                remainingPacketLenght -= 4;
                dataLen -= 4;

                std::cout << "          AddressCount: " << addrCount << std::endl;

                uint8_t protocolType;
                memcpy(&protocolType, packetPointer++, 1);
                remainingPacketLenght--;
                dataLen--;

                uint8_t protocolLength;
                memcpy(&protocolLength, packetPointer++, 1);
                remainingPacketLenght--;
                dataLen--;

                switch(protocolType){
                    case 1:{
                        std::cout << "          Protocol Type: NLPID format" << " | ";

                        /* therefore only 1 byte for protocol, after operation, shift */
                        uint8_t protocol;
                        memcpy(&protocol, packetPointer++, 1);
                        remainingPacketLenght--;
                        dataLen--;

                        switch(protocol){
                            case 0x81:{
                                std::cout << "Protocol: ISO CLNS" << std::endl;
                                break;
                            }
                            case 0xCC:{
                                std::cout << "Protocol: IP" << " | ";

                                uint16_t addrLen;
                                memcpy(&addrLen, packetPointer, 2);
                                addrLen = ntohs(addrLen);
                                packetPointer += 2;
                                remainingPacketLenght -= 2;
                                dataLen -= 2;

                                struct in_addr *addr = (struct in_addr *) malloc(sizeof(struct in_addr));

                                /* copy IP from packet to memory and move packetPointer */
                                memcpy(addr, packetPointer, 4);
                                packetPointer += 4;
                                remainingPacketLenght -= 4;
                                dataLen -= 4;

                                /* get address to string */
                                char ipv4addr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, addr, ipv4addr, INET_ADDRSTRLEN);

                                std::cout << "IP Address: " << ipv4addr;

                                free(addr);
                                break;
                            }
                        }
                        break;
                    }
                    case 2:{
                        std::cout << "          Protocol Type: 802.2 format" << " | ";
                        uint64_t protocol;
                        memcpy(&protocol, packetPointer, 8);
                        /* get to format "normal people" use */
                        protocol = htobe64(protocol);
                        packetPointer += 8;
                        remainingPacketLenght -= 8;
                        dataLen -= 8;

                        std::cout << "Protocol code: 0x" << std::hex << protocol;

                        break;
                    }
                    default:{
                        std::cout << "          Protocol Type: Unknown" << " | " ;
                    }

                }

                std::cout << std::endl;

                /* get the rest of TLV data */
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;
                break;
            }
            default:{
                /* unknown TLV? jump over */
                packetPointer += dataLen;
                remainingPacketLenght -= dataLen;
                dataLen = 0;
                break;
            }
        }


    }
    return 0;
}

void sniffer::mProcessPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    /* get the ethernet frame head */
    struct ether_header *head = (struct ether_header *) packet;
    bool lldpProtocol = false;
    bool cdpProtocol = false;
    /* type of ethernet header */
    uint8_t ethTypeFlag = 0;

    /* WOLOLO! Unit has been converted to the right endian */
    uint16_t ethType = ntohs(head->ether_type);

    uint16_t cdpLen = ethType - 8;


    /* check if it is ethernet II or IEEE 802.3 */
    /* IEEE 802.3 */
    if(1500 >= ethType){
        ethTypeFlag = ETHERNET_IEEE;

        /* get type of payload */
        uint16_t cdpType;
        /* copy type from CDP */
        /* 6 for Dest Addr + 6 for Src Addr + 2 for Length +
         * + 1 for DSAP + 1 for SSAP + 1 for Control +
         * + 3 for Vendor Code == 20 , this is index of our local code
         * src: http://www.wildpackets.com/resources/compendium/ethernet/frame_snap_iee8023#SSAP */
        memcpy(&cdpType, (packet + 20), 2);
        cdpType = ntohs(cdpType);
        if(CDP_CODE == cdpType){
            cdpProtocol = true;
        } else {
            return;
        }
    /* ETHER II */
    } else if(1536 <= ethType){
        ethTypeFlag = ETHERNET_II;

        /* if type of payload is LLDP */
        if(LLDP_CODE == ethType){
            lldpProtocol = true;
        } else {
            return;
        }

    /* invalid ethernet frame */
    } else {
        return;
    }

    std::cout   << "******************************" << std::endl;
    /* ethernet header */
    std::cout   << ((ethTypeFlag == ETHERNET_IEEE)?"Ethernet 802.3 header: ":"Ethernet II header: ") << std::endl;
    std::cout   << "Destination MAC address: " << ether_ntoa((struct ether_addr *) head->ether_dhost)
                << " | Source MAC address: " << ether_ntoa((struct ether_addr *) head->ether_shost)
                << ((ethTypeFlag == ETHERNET_IEEE)?" | Payload length: ":" | Payload type: ")
                << "0x" << std::hex << ethType << std::endl;

    /* CDP or LLDP dump */
    std::cout   << ((cdpProtocol)?"Payload: CDP protocol":"Payload: LLDP protocol") << std::endl;

    if(lldpProtocol) {
        /* pass pointer to packet without ethernet header */
        mParseLLDP(packet + ETHER_HEADER_SIZE);
    } else {
        mParseCDP(packet + 22, cdpLen);
    }

    std::cout << "******************************" << std::endl;
}

int sniffer::mStartSniffing(){
    char errBuff[PCAP_ERRBUF_SIZE];
    char *device = (char *)mInterfaceFlag.second.c_str();

    /* netmask of the sniffing device */
    bpf_u_int32 mask;
    /* IP of the sniffing device */
    bpf_u_int32 IPAddr;

    if(-1 == pcap_lookupnet(device, &IPAddr, &mask, errBuff)){
        std::cerr << "Failed to acquire netmask" << std::endl;
        IPAddr = 0;
        mask = 0;
    }

    /* open capture in promiscuous mode */
    pcap_t *handler;
    if(NULL == (handler = pcap_open_live(device, BUFSIZ, 1, 1000, errBuff))){
        std::cerr << "Failed to open device" << std::endl;
        return E_ESTABILISHINGCONNECTION;
    }

    /* system is missing link layer headers */
    if(DLT_EN10MB != pcap_datalink(handler)){
        std::cerr << "Missing required layers" << std::endl;
        return E_ESTABILISHINGCONNECTION;
    }

    /* get packets */
    pcap_loop(handler, -1, mProcessPacket, NULL);

    /* clean up */
    pcap_close(handler);

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

//    std::cout << "******DEBUG******" << std::endl;
//    std::cout << mInterfaceFlag.second << std::endl;
//    std::cout << mPlatformFlag.second << std::endl;
//    std::cout << mVersionFlag.second;
//    std::cout << mDeviceIdFlag.second << std::endl;
//    char str[INET_ADDRSTRLEN];
//    inet_ntop(AF_INET, &mAddressFlag.second.sin_addr, str, INET_ADDRSTRLEN);
//    std::cout << str << std::endl;
//    std::cout << "******DEBUG******" << std::endl;

    /* Missing the only required argument, therefore I must quit the app */
    if(!mInterfaceFlag.first){
        return E_MISSINGREQUIREDARG;
    }

    return mStartSniffing();
}
