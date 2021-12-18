#pragma once
#include <tins/tins.h>
#include <iostream>
#include <sstream>
#include "ProtocolDeterminer.h"
#include "ColorPicker.h"

using namespace Tins;

class PacketPrinter
{
    static const char* type_ieee802_3(PDU* pdu, std::stringstream& ss);
    static const char* type_ethernet2(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_llc(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_ip(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_ipv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_arp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_icmp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_icmpv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_tcp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static const char* type_udp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);

public:
    static const char* protocol_switch(PDU::PDUType currPDUType, PDU* currPDU, PDU* nextPDU,
                                std::stringstream& ss, std::string& altProtocolName);
};
