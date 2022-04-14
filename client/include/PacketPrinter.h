#pragma once
#include <tins/tins.h>
#include <sstream>
#include "ProtocolDeterminer.h"

using namespace Tins;

class PacketPrinter
{
private:
    static uint64_t _packet_number;

    // Only the relevant protocols are here
    static void edit_ss_ieee802_3(PDU* pdu, std::stringstream& ss);
    static void edit_ss_ethernet2(PDU* pdu, std::stringstream& ss);
    static void edit_ss_ip(PDU* pdu, std::stringstream& ss);
    static void edit_ss_ipv6(PDU* pdu, std::stringstream& ss);
    static void edit_ss_tcp(PDU* pdu, std::stringstream& ss);
    static void edit_ss_udp(PDU* pdu, std::stringstream& ss);

    static protocol_properties get_protocol_properties(PDU::PDUType currPDUType, PDU* currPDU,
                                std::stringstream& ss);
public:
    static void print_packet(const Packet& packet);
    static void reset_packet_number();
};
