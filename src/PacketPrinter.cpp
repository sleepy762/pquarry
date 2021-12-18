#include "PacketPrinter.h"

// Adds relevant info to the string stream and returns a color for the output
const char* PacketPrinter::protocol_switch(PDU::PDUType currPDUType, PDU* currPDU, PDU* nextPDU, 
    std::stringstream& ss, std::string& altProtocolName)
{
    PDU::PDUType nextPDUType = nextPDU != nullptr ? nextPDU->pdu_type() : currPDU->UNKNOWN;
    // When possible, this variable will hold a more specific protocol name compared to the list `protocols`
    const char* colorPtr = nullptr;

    switch (currPDUType)
    {
    case currPDU->IEEE802_3:
        colorPtr = PacketPrinter::type_ieee802_3(currPDU, ss);
        break;

    case currPDU->ETHERNET_II:
        colorPtr = PacketPrinter::type_ethernet2(currPDU, ss, altProtocolName);
        break;

    case currPDU->LLC:
        colorPtr = PacketPrinter::type_llc(currPDU, ss, altProtocolName);
        break;

    case currPDU->IP:
        colorPtr = PacketPrinter::type_ip(currPDU, ss, altProtocolName);
        break;

    case currPDU->IPv6:
        colorPtr = PacketPrinter::type_ipv6(currPDU, ss, altProtocolName);
        break;

    case currPDU->ARP:
        colorPtr = PacketPrinter::type_arp(currPDU, ss, altProtocolName);
        break;

    case currPDU->ICMP:
        colorPtr = PacketPrinter::type_icmp(currPDU, ss, altProtocolName);
        break;

    case currPDU->ICMPv6:
        colorPtr = PacketPrinter::type_icmpv6(currPDU, ss, altProtocolName);
        break;

    case currPDU->TCP:
        colorPtr = PacketPrinter::type_tcp(currPDU, ss, altProtocolName);
        break;

    case currPDU->UDP:
        colorPtr = PacketPrinter::type_udp(currPDU, ss, altProtocolName);
        break;

    default: // Unknown PDU
        colorPtr = ColorPicker::get_color_by_pdu_type(currPDUType);
        break;
    }
    return colorPtr;
}

const char* PacketPrinter::type_ieee802_3(PDU* pdu, std::stringstream& ss)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return nullptr;
    }
    
    IEEE802_3* ieee802_3 = pdu->find_pdu<IEEE802_3>();

    ss << ieee802_3->src_addr() << "->";
    // Print 'Broadcast' instead of the broadcast address
    if (ieee802_3->dst_addr() == ieee802_3->BROADCAST)
    {
        ss << "Broadcast";
    }
    else
    {
        ss << ieee802_3->dst_addr();
    }
    ss << "\t";
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_ethernet2(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return nullptr;
    }

    EthernetII* eth2 = pdu->find_pdu<EthernetII>();
    // Determine packet type
    altProtocolName = std::string(ProtocolDeterminer::eth2_type_string(eth2->payload_type()));

    ss << eth2->src_addr() << "->";
    // Print 'Broadcast' instead of the broadcast address
    if (eth2->dst_addr() == eth2->BROADCAST)
    {
        ss << "Broadcast\t";
    }
    else
    {
        ss << eth2->dst_addr();
    }
    ss << "\t\t";
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_llc(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    LLC* llc = pdu->find_pdu<LLC>();
    altProtocolName = std::string(ProtocolDeterminer::llc_modifier_func_string(llc->modifier_function()));
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_ip(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    IP* ip = pdu->find_pdu<IP>();
    altProtocolName = std::string(ProtocolDeterminer::ip_protocol_string(ip->protocol()));
    ss << ip->src_addr() << "->" << ip->dst_addr() << "\t";
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_ipv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    IPv6* ipv6 = pdu->find_pdu<IPv6>();
    ss << ipv6->src_addr() << "->" << ipv6->dst_addr() << "\t";
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_arp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    ARP* arp = pdu->find_pdu<ARP>();
    // print response/request
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_icmp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    ICMP* icmp = pdu->find_pdu<ICMP>();
    // print type
    ss << "\t\t";
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_icmpv6(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    ICMPv6* icmpv6 = pdu->find_pdu<ICMPv6>();
    // print type
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_tcp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    TCP* tcp = pdu->find_pdu<TCP>();
    ss << tcp->sport() << "->" << tcp->dport() << "\t";
    
    // Check if src port corresponds to a protocol, if not then use the dst port
    if (ProtocolDeterminer::check_if_alt_protocol_exists(tcp->sport()))
    {
        altProtocolName = std::string(ProtocolDeterminer::port_protocol_string(tcp->sport()));
        return ColorPicker::get_color_by_port(tcp->sport());
    }
    else if (ProtocolDeterminer::check_if_alt_protocol_exists(tcp->dport()))
    {
        altProtocolName = std::string(ProtocolDeterminer::port_protocol_string(tcp->dport()));
        return ColorPicker::get_color_by_port(tcp->dport());
    }
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}

const char* PacketPrinter::type_udp(PDU* pdu, std::stringstream& ss, std::string& altProtocolName)
{
    UDP* udp = pdu->find_pdu<UDP>();
    ss << udp->sport() << "->" << udp->dport() << "\t";
    
    // Check if src port corresponds to a protocol, if not then use the dst port
    if (ProtocolDeterminer::check_if_alt_protocol_exists(udp->sport()))
    {
        altProtocolName = std::string(ProtocolDeterminer::port_protocol_string(udp->sport()));
        return ColorPicker::get_color_by_port(udp->sport());
    }
    else if (ProtocolDeterminer::check_if_alt_protocol_exists(udp->dport()))
    {
        altProtocolName = std::string(ProtocolDeterminer::port_protocol_string(udp->dport()));
        return ColorPicker::get_color_by_port(udp->dport());
    }
    return ColorPicker::get_color_by_pdu_type(pdu->pdu_type());
}
