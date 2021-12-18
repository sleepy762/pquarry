#include "ColorPicker.h"

const char* ColorPicker::get_color_by_pdu_type(PDU::PDUType type)
{
    switch (type)
    {
    case PDU::PDUType::IEEE802_3:
    case PDU::PDUType::ETHERNET_II:
    case PDU::PDUType::LLC:
        return ANSI_RGB(255,255,214);
        break;

    case PDU::PDUType::IP:
    case PDU::PDUType::IPv6:
        return ANSI_RGB(255,217,214);
        break;

    case PDU::PDUType::ARP:
        return ANSI_RGB(255,214,171);
        break;
        
    case PDU::PDUType::ICMP:
        return ANSI_RGB(0,255,0);
        break;

    case PDU::PDUType::ICMPv6:
        return ANSI_RGB(240,171,255);
        break;

    case PDU::PDUType::TCP:
        return ANSI_RGB(99,219,255);
        break;

    case PDU::PDUType::UDP:
        return ANSI_RGB(99,125,255);
        break;

    default:
        return DEFAULT_COLOR;
        break;
    }
}

const char* ColorPicker::get_color_by_port(uint16_t port)
{
    switch (port)
    {
    case 20: // FTP
    case 21: // FTP
    case 69: // TFTP
        return ANSI_RGB(255,179,222);
        break;

    case 22: // SSH
        return ANSI_RGB(0,255,255);
        break;

    case 23: // Telnet
        return ANSI_RGB(155,255,0);
        break;

    case 53: // DNS
    case 5353: // MDNS
        return ANSI_RGB(0,255,174);
        break;

    case 67: // DHCP
    case 68: // DHCP
        return ANSI_RGB(255,157,0);
        break;

    case 80: // HTTP
        return ANSI_RGB(135,255,135);
        break;

    case 137: // NBNS
    case 138: // NBDS
    case 139: // NBSS
        return ANSI_RGB(255,255,0);
        break;

    case 443: // HTTPS
    case 989: // FTPS
    case 990: // FTPS
        return ANSI_RGB(209,184,255);
        break;

    default:
        return DEFAULT_COLOR;
        break;
    }
}
