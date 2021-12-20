#include "ColorPicker.h"

// Default color values
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
