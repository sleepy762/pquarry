#pragma once
#include <tins/tins.h>
#include <iostream>
#include <sstream>
#include "ProtocolDeterminer.h"

using namespace Tins;

class PacketPrinter
{
    static void type_ieee802_3(PDU* pdu, std::stringstream& ss);
    static void type_ethernet2(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_llc(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_ip(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_ipv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_arp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_icmp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_icmpv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_tcp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    static void type_udp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    // static void type_raw(PDU* pdu, std::stringstream& ss, std::string& altProtocolName);
    // static void type_unknown(PDU* pdu);

public:
    static std::string protocol_switch(PDU::PDUType currPDUType, PDU* currPDU, PDU* nextPDU,
                                std::stringstream& ss);
};
