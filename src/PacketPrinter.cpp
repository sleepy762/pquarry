#include "PacketPrinter.h"

// Adds relevant info to the string stream and returns an alternative protocol name, when it exists
std::string PacketPrinter::protocol_switch(PDU::PDUType currPDUType, PDU* currPDU, PDU* nextPDU, std::stringstream& ss)
{
    PDU::PDUType nextPDUType = nextPDU != nullptr ? nextPDU->pdu_type() : currPDU->UNKNOWN;
    // When possible, this variable will hold a more specific protocol name compared to the list `protocols`
    std::string altProtocolName = "";

    switch (currPDUType)
    {
    case currPDU->IEEE802_3:
        PacketPrinter::type_ieee802_3(currPDU, ss);
        break;

    case currPDU->ETHERNET_II:
        PacketPrinter::type_ethernet2(currPDU, ss, altProtocolName);
        break;

    case currPDU->LLC:
        PacketPrinter::type_llc(currPDU, ss, altProtocolName);
        break;

    case currPDU->IP:
        PacketPrinter::type_ip(currPDU, ss, altProtocolName);
        break;

    case currPDU->IPv6:
        PacketPrinter::type_ipv6(currPDU, ss, altProtocolName);
        break;

    case currPDU->ARP:
        PacketPrinter::type_arp(currPDU, ss, altProtocolName);
        break;

    case currPDU->ICMP:
        PacketPrinter::type_icmp(currPDU, ss, altProtocolName);
        break;

    case currPDU->ICMPv6:
        PacketPrinter::type_icmpv6(currPDU, ss, altProtocolName);
        break;

    case currPDU->TCP:
        PacketPrinter::type_tcp(currPDU, ss, altProtocolName);
        break;

    case currPDU->UDP:
        PacketPrinter::type_udp(currPDU, ss, altProtocolName);
        break;

    // case currPDU->RAW:
    //     // TODO
    //     //PacketPrinter::type_raw(currPDU);
    //     break;

    default: // Unknown PDU
        break;
    }

    return altProtocolName;
}

void PacketPrinter::type_ieee802_3(PDU* pdu, std::stringstream& ss)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return;
    }
    
    IEEE802_3* ieee802_3 = pdu->find_pdu<IEEE802_3>();
    ss << ieee802_3->src_addr() << "->" << ieee802_3->dst_addr() << "\t";
}

void PacketPrinter::type_ethernet2(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return;
    }

    EthernetII* eth2 = pdu->find_pdu<EthernetII>();
    // Determine packet type
    altProtocolName = std::string(ProtocolDeterminer::eth2_type_string(eth2->payload_type()));
    ss << eth2->src_addr() << "->" << eth2->dst_addr() << "\t";
}

void PacketPrinter::type_llc(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    LLC* llc = pdu->find_pdu<LLC>();
    altProtocolName = std::string(ProtocolDeterminer::llc_modifier_func_string(llc->modifier_function()));
}

void PacketPrinter::type_ip(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    IP* ip = pdu->find_pdu<IP>();
    altProtocolName = std::string(ProtocolDeterminer::ip_protocol_string(ip->protocol()));
    ss << ip->src_addr() << "->" << ip->dst_addr() << "\t";
}

void PacketPrinter::type_ipv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    IPv6* ipv6 = pdu->find_pdu<IPv6>();
    ss << ipv6->src_addr() << "->" << ipv6->dst_addr() << "\t";
}

void PacketPrinter::type_arp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    ARP* arp = pdu->find_pdu<ARP>();
    // print response/request
}

void PacketPrinter::type_icmp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    ICMP* icmp = pdu->find_pdu<ICMP>();
    // print type
}

void PacketPrinter::type_icmpv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    ICMPv6* icmpv6 = pdu->find_pdu<ICMPv6>();
    // print type
}

void PacketPrinter::type_tcp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    TCP* tcp = pdu->find_pdu<TCP>();
    ss << tcp->sport() << "->" << tcp->dport() << "\t";
    
    // Check if src port corresponds to a protocol, if not then check the dst port
    std::string tmp = std::string(ProtocolDeterminer::port_protocol_string(tcp->sport()));
    altProtocolName = (tmp != "") ?
        tmp : std::string(ProtocolDeterminer::port_protocol_string(tcp->dport()));
}

void PacketPrinter::type_udp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    UDP* udp = pdu->find_pdu<UDP>();
    ss << udp->sport() << "->" << udp->dport() << "\t";
    
    // Check if src port corresponds to a protocol, if not then check the dst port
    std::string tmp = std::string(ProtocolDeterminer::port_protocol_string(udp->sport()));
    altProtocolName = (tmp != "") ?
        tmp : std::string(ProtocolDeterminer::port_protocol_string(udp->dport()));
}

// void PacketPrinter::type_raw(PDU* pdu)
// {
//     // cast RAW pdus with regards to port, see comment below + refer to the list of ports
//     // MDNS, DNS, HTTP, HTTPS, IGMPv3, TLS, QUIC, NBNS, DHCP, SSDP.....
// }
