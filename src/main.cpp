#include <tins/tins.h>
#include <iostream>
#include <unistd.h>
#include <list>
#include <chrono>

using namespace Tins;

std::list<PDU*> savedPDUs;

bool callback(const PDU& pdu)
{
    // Initial packet number
    static int packetNumber = 1;
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Print packet serial number
    std::cout << packetNumber << "\t";

    PDU* originalPDU = pdu.clone();
    // Gather data from all the protocols in the list of PDUs
    PDU* inner = originalPDU;
    while (inner != nullptr)
    {
        PDU::PDUType innerType = inner->pdu_type();
        PDU* nextInnerPDU = inner->inner_pdu();
        PDU::PDUType nextType = nextInnerPDU != nullptr ? nextInnerPDU->pdu_type() : pdu.UNKNOWN;

        // Variable for each protocol, because they cannot be created inside the switch
        IEEE802_3* ieee802_3; EthernetII* eth2; LLC* llc;
        IP* ip; IPv6* ipv6; ARP* arp; ICMP* icmp; ICMPv6* icmpv6; DHCP* dhcp; DHCPv6* dhcpv6;
        TCP* tcp; UDP* udp;
        switch (innerType)
        {
            // cast RAW pdus with regards to port, see comment below + refer to the list of ports
            // MDNS, DNS, HTTP, HTTPS, IGMPv3, TLS, QUIC, NBNS, DHCP, SSDP.....
        case pdu.IEEE802_3:
            // Don't print mac addresses if the IP protocol exists
            if (inner->find_pdu<IP>() != nullptr || inner->find_pdu<IPv6>() != nullptr) break;
            ieee802_3 = inner->find_pdu<IEEE802_3>();
            std::cout << ieee802_3->src_addr() << "->" << ieee802_3->dst_addr() << "\t";
            break;

        case pdu.ETHERNET_II:
            if (inner->find_pdu<IP>() != nullptr || inner->find_pdu<IPv6>() != nullptr) break;
            eth2 = inner->find_pdu<EthernetII>();
            std::cout << eth2->src_addr() << "->" << eth2->dst_addr() << "\t";
            break;

        case pdu.LLC:
            llc = inner->find_pdu<LLC>();
            // print modifier
            break;

        case pdu.IP:
            ip = inner->find_pdu<IP>();
            std::cout << ip->src_addr() << "->" << ip->dst_addr() << "\t";
            break;

        case pdu.IPv6:
            ipv6 = inner->find_pdu<IPv6>();
            std::cout << ipv6->src_addr() << "->" << ipv6->dst_addr() << "\t";
            break;

        case pdu.ARP:
            arp = inner->find_pdu<ARP>();
            // print response/request
            break;

        case pdu.ICMP:
            icmp = inner->find_pdu<ICMP>();
            // print type
            break;
        case pdu.ICMPv6:
            icmpv6 = inner->find_pdu<ICMPv6>();
            // print type
            break;

        case pdu.TCP:
            tcp = inner->find_pdu<TCP>();
            std::cout << tcp->sport() << "->" << tcp->dport() << "\t";
            break;

        case pdu.UDP:
            udp = inner->find_pdu<UDP>();
            std::cout << udp->sport() << "->" << udp->dport() << "\t";
            break;

        case pdu.RAW:
            // cast by port
            break;

        default: // Unknown PDU
            break;
        }

        // Store the sequence of protocols
        if (innerType != pdu.RAW)
        {
            protocols.push_back(innerType);
        }

        // Advance the pdu list
        inner = nextInnerPDU;
    }
    std::cout << originalPDU->size() << "\t" << Utils::to_string(protocols.back()) << std::endl;

    savedPDUs.push_back(originalPDU);
    packetNumber++;
    return true;
}

int main(int argc, char* argv[])
{
    if (getuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }
    if (argc != 2)
    {
        std::cout << "Usage: " << *argv << " <interface>" << std::endl;
        return 1;
    }
    Sniffer(argv[1]).sniff_loop(callback);
    return 0;
}
