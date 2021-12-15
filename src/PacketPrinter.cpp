#include "PacketPrinter.h"

void PacketPrinter::protocol_switch(PDU::PDUType currPDUType, PDU* currPDU, PDU* nextPDU)
{
    PDU::PDUType nextPDUType = nextPDU != nullptr ? nextPDU->pdu_type() : currPDU->UNKNOWN;

    switch (currPDUType)
    {
    case currPDU->IEEE802_3:
        PacketPrinter::type_ieee802_3(currPDU);
        break;

    case currPDU->ETHERNET_II:
        PacketPrinter::type_ethernet2(currPDU);
        break;

    case currPDU->LLC:
        PacketPrinter::type_llc(currPDU);
        break;

    case currPDU->IP:
        PacketPrinter::type_ip(currPDU);
        break;

    case currPDU->IPv6:
        PacketPrinter::type_ipv6(currPDU);
        break;

    case currPDU->ARP:
        PacketPrinter::type_arp(currPDU);
        break;

    case currPDU->ICMP:
        PacketPrinter::type_icmp(currPDU);
        break;

    case currPDU->ICMPv6:
        PacketPrinter::type_icmpv6(currPDU);
        break;

    case currPDU->TCP:
        PacketPrinter::type_tcp(currPDU);
        break;

    case currPDU->UDP:
        PacketPrinter::type_udp(currPDU);
        break;

    case currPDU->RAW:
        // TODO
        //PacketPrinter::type_raw(currPDU);
        break;

    default: // Unknown PDU
        break;
    }
}

void PacketPrinter::type_ieee802_3(PDU* pdu)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return;
    }
    
    IEEE802_3* ieee802_3 = pdu->find_pdu<IEEE802_3>();
    std::cout << ieee802_3->src_addr() << "->" << ieee802_3->dst_addr() << "\t";
}

void PacketPrinter::type_ethernet2(PDU* pdu)
{
    // Don't print mac addresses if the IP protocol exists
    if (pdu->find_pdu<IP>() != nullptr || pdu->find_pdu<IPv6>() != nullptr)
    {
        return;
    }

    // Determine packet type using eth2->payload_type() (LLDP (0x88cc), ieee1905 (0x893a), 0x1ee4....)
    // Push into protocols list (pass as parameter)
    EthernetII* eth2 = pdu->find_pdu<EthernetII>();
    std::cout << eth2->src_addr() << "->" << eth2->dst_addr() << "\t";
}

void PacketPrinter::type_llc(PDU* pdu)
{
    LLC* llc = pdu->find_pdu<LLC>();
    // print modifier
}

void PacketPrinter::type_ip(PDU* pdu)
{
    IP* ip = pdu->find_pdu<IP>();
    std::cout << ip->src_addr() << "->" << ip->dst_addr() << "\t";
}

void PacketPrinter::type_ipv6(PDU* pdu)
{
    IPv6* ipv6 = pdu->find_pdu<IPv6>();
    std::cout << ipv6->src_addr() << "->" << ipv6->dst_addr() << "\t";
}

void PacketPrinter::type_arp(PDU* pdu)
{
    ARP* arp = pdu->find_pdu<ARP>();
    // print response/request
}

void PacketPrinter::type_icmp(PDU* pdu)
{
    ICMP* icmp = pdu->find_pdu<ICMP>();
    // print type
}

void PacketPrinter::type_icmpv6(PDU* pdu)
{
    ICMPv6* icmpv6 = pdu->find_pdu<ICMPv6>();
    // print type
}

void PacketPrinter::type_tcp(PDU* pdu)
{
    TCP* tcp = pdu->find_pdu<TCP>();
    std::cout << tcp->sport() << "->" << tcp->dport() << "\t";
}

void PacketPrinter::type_udp(PDU* pdu)
{
    UDP* udp = pdu->find_pdu<UDP>();
    std::cout << udp->sport() << "->" << udp->dport() << "\t";
}

void PacketPrinter::type_raw(PDU* pdu)
{
    // cast RAW pdus with regards to port, see comment below + refer to the list of ports
    // MDNS, DNS, HTTP, HTTPS, IGMPv3, TLS, QUIC, NBNS, DHCP, SSDP.....
}
