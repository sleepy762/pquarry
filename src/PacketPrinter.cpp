#include "PacketPrinter.h"

// Adds relevant info to the string stream and returns a color for the output
protocol_properties PacketPrinter::get_protocol_properties(PDU::PDUType currPDUType, PDU* currPDU,
    std::stringstream& ss)
{
    // When possible, this variable will hold a more specific protocol name compared to the list `protocols`
    protocol_properties properties = NULL_PROPERTIES;

    switch (currPDUType)
    {
    case currPDU->IEEE802_3:
        PacketPrinter::edit_ss_ieee802_3(currPDU, ss);
        break;

    case currPDU->ETHERNET_II:
        PacketPrinter::edit_ss_ethernet2(currPDU, ss);
        properties = ProtocolDeterminer::get_protocol_properties_by_type(currPDU->pdu_type(), 
            currPDU->find_pdu<EthernetII>()->payload_type());
        break;

    case currPDU->LLC:
        PacketPrinter::edit_ss_llc(currPDU, ss);
        break;

    case currPDU->IP:
        PacketPrinter::edit_ss_ip(currPDU, ss);
        properties = ProtocolDeterminer::get_protocol_properties_by_type(currPDU->pdu_type(), 
            currPDU->find_pdu<IP>()->protocol());
        break;

    case currPDU->IPv6:
        PacketPrinter::edit_ss_ipv6(currPDU, ss);
        break;

    case currPDU->ARP:
        PacketPrinter::edit_ss_arp(currPDU, ss);
        break;

    case currPDU->ICMP:
        PacketPrinter::edit_ss_icmp(currPDU, ss);
        break;

    case currPDU->ICMPv6:
        PacketPrinter::edit_ss_icmpv6(currPDU, ss);
        break;

    case currPDU->TCP:
    {
        PacketPrinter::edit_ss_tcp(currPDU, ss);
        TCP* tcp = currPDU->find_pdu<TCP>();
        properties = ProtocolDeterminer::get_protocol_properties_by_ports(tcp->sport(), tcp->dport());
        break;
    }

    case currPDU->UDP:
    {
        PacketPrinter::edit_ss_udp(currPDU, ss);
        UDP* udp = currPDU->find_pdu<UDP>();
        properties = ProtocolDeterminer::get_protocol_properties_by_ports(udp->sport(), udp->dport());
        break;
    }
    
    default:
        break;
    } // switch (currPDUType)

    if (properties.protocolColor == nullptr)
    {
        properties.protocolColor = ColorPicker::get_color_by_pdu_type(currPDUType);
    }

    return properties;
}

void PacketPrinter::edit_ss_ieee802_3(PDU* pdu, std::stringstream& ss)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return;
    }
    
    IEEE802_3* ieee802_3 = pdu->find_pdu<IEEE802_3>();

    // Append relevant data to the string stream
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
}

void PacketPrinter::edit_ss_ethernet2(PDU* pdu, std::stringstream& ss)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return;
    }

    EthernetII* eth2 = pdu->find_pdu<EthernetII>();

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
}

void PacketPrinter::edit_ss_llc(PDU* pdu, std::stringstream& ss)
{
    LLC* llc = pdu->find_pdu<LLC>();
    // maybe add something to the string stream
    (void*)llc;
}

void PacketPrinter::edit_ss_ip(PDU* pdu, std::stringstream& ss)
{
    IP* ip = pdu->find_pdu<IP>();
    ss << ip->src_addr() << "->" << ip->dst_addr() << "\t";
}

void PacketPrinter::edit_ss_ipv6(PDU* pdu, std::stringstream& ss)
{
    IPv6* ipv6 = pdu->find_pdu<IPv6>();
    ss << ipv6->src_addr() << "->" << ipv6->dst_addr() << "\t";
}

void PacketPrinter::edit_ss_arp(PDU* pdu, std::stringstream& ss)
{
    ARP* arp = pdu->find_pdu<ARP>();
    // maybe add some arp info
    (void*)arp;
}

void PacketPrinter::edit_ss_icmp(PDU* pdu, std::stringstream& ss)
{
    ICMP* icmp = pdu->find_pdu<ICMP>();
    ss << "\t\t";
}

void PacketPrinter::edit_ss_icmpv6(PDU* pdu, std::stringstream& ss)
{
    ICMPv6* icmpv6 = pdu->find_pdu<ICMPv6>();
    // maybe add some info
    (void*)icmpv6;
}

void PacketPrinter::edit_ss_tcp(PDU* pdu, std::stringstream& ss)
{
    TCP* tcp = pdu->find_pdu<TCP>();
    ss << tcp->sport() << "->" << tcp->dport() << "\t";
}

void PacketPrinter::edit_ss_udp(PDU* pdu, std::stringstream& ss)
{
    UDP* udp = pdu->find_pdu<UDP>();
    ss << udp->sport() << "->" << udp->dport() << "\t";
}
