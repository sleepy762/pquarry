#include "PacketPrinter.h"
#include <iostream>
#include <list>

uint64_t PacketPrinter::_packet_number = 1;

void PacketPrinter::print_packet(const Packet& packet)
{
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Holds the packet output line
    std::stringstream ss;
    // Packet serial number
    ss << _packet_number << '\t';

    protocol_properties properties;

    std::unique_ptr<PDU> originalPDU(packet.pdu()->clone());
    // Gather data from all the protocols in the list of PDUs
    // Each PDU in the chain has certain data that we might want
    PDU* inner = originalPDU.get();
    while (inner != nullptr)
    {
        PDU::PDUType innerType = inner->pdu_type();

        // Store the sequence of protocols
        if (innerType != PDU::PDUType::RAW)
        {
            properties = PacketPrinter::get_protocol_properties(innerType, inner, ss);
            protocols.push_back(innerType);
        }

        // Advance the pdu list
        inner = inner->inner_pdu();
    }
    ss << originalPDU->size() << '\t';

    // Append alternative protocol name, if it exists
    if (properties.protocolString != nullptr)
    {
        ss << properties.protocolString << '(' << Utils::to_string(protocols.back()) << ')';
    }
    else
    {
        ss << Utils::to_string(protocols.back());
    }

    // Output the entire packet string stream
    std::cout << properties.protocolColor << ss.str() << RESET_COLOR << '\n';

    _packet_number++;
}

void PacketPrinter::reset_packet_number()
{
    _packet_number = 1;
}

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

    case currPDU->IP:
        PacketPrinter::edit_ss_ip(currPDU, ss);
        properties = ProtocolDeterminer::get_protocol_properties_by_type(currPDU->pdu_type(), 
            currPDU->find_pdu<IP>()->protocol());
        break;

    case currPDU->IPv6:
        PacketPrinter::edit_ss_ipv6(currPDU, ss);
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
        properties.protocolColor = ProtocolDeterminer::get_color_by_pdu_type(currPDUType);
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
