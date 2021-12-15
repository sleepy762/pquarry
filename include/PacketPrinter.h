#pragma once
#include <tins/tins.h>
#include <iostream>

using namespace Tins;

class PacketPrinter
{
    static void type_ieee802_3(PDU* pdu);
    static void type_ethernet2(PDU* pdu);
    static void type_llc(PDU* pdu);
    static void type_ip(PDU* pdu);
    static void type_ipv6(PDU* pdu);
    static void type_arp(PDU* pdu);
    static void type_icmp(PDU* pdu);
    static void type_icmpv6(PDU* pdu);
    static void type_tcp(PDU* pdu);
    static void type_udp(PDU* pdu);
    static void type_raw(PDU* pdu);
    // static void type_unknown(PDU* pdu);

public:
    static void protocol_switch(PDU::PDUType currPDUType, PDU* currPDU, PDU* nextPDU);
};
