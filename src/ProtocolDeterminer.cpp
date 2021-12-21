#include "ProtocolDeterminer.h"

const protocol_properties NULL_PROPERTIES = { nullptr, nullptr };

// The maps contain some identifier as the key, the value is the 'protocol_properties' struct
// which contains a string for the protocol name, and another string for the ANSI color string
// 'nullptr' in the color field means that the default color of the layer will be used (see the ColorPicker class)

const std::map<uint16_t, protocol_properties> ProtocolDeterminer::_eth2_types =
{
    { 0x88cc, { "LLDP", nullptr } }
};

const std::map<uint16_t, protocol_properties> ProtocolDeterminer::_ip_protocols = 
{
    { 0x0002, { "IGMP", nullptr } }
};

// This includes both UDP and TCP ports, which may cause incorrect determinations
const std::map<uint16_t, protocol_properties> ProtocolDeterminer::_port_protocols =
{
    { 20, { "FTP", ANSI_RGB(255,179,222) } },
    { 21, { "FTP", ANSI_RGB(255,179,222) } },
    { 22, { "SSH", ANSI_RGB(0,255,255) } },
    { 23, { "Telnet", ANSI_RGB(155,255,0) } },
    { 25, { "SMTP", DEFAULT_COLOR } },
    { 50, { "IPSec", DEFAULT_COLOR } },
    { 51, { "IPSec", DEFAULT_COLOR } },
    { 53, { "DNS", ANSI_RGB(0,255,174) } },
    { 67, { "DHCP", ANSI_RGB(255,157,0) } },
    { 68, { "DHCP", ANSI_RGB(255,157,0) } },
    { 69, { "TFTP", ANSI_RGB(255,179,222) } },
    { 80, { "HTTP", ANSI_RGB(135,255,135) } },
    { 110, { "POP3", DEFAULT_COLOR } },
    { 119, { "NNTP", DEFAULT_COLOR } },
    { 123, { "NTP", DEFAULT_COLOR } },
    { 137, { "NBNS", ANSI_RGB(255,255,0) } },
    { 138, { "NBDS", ANSI_RGB(255,255,0) } },
    { 139, { "NBSS", ANSI_RGB(255,255,0) } },
    { 143, { "IMAP4", DEFAULT_COLOR } },
    { 161, { "SNMP", DEFAULT_COLOR } },
    { 162, { "SNMP", DEFAULT_COLOR } },
    { 389, { "LDAP", DEFAULT_COLOR } },
    { 443, { "HTTPS", ANSI_RGB(209,184,255) } },
    { 989, { "FTPS", ANSI_RGB(209,184,255) } },
    { 990, { "FTPS", ANSI_RGB(209,184,255) } },
    { 1900, { "SSDP", nullptr } },
    { 3389, { "RDP", DEFAULT_COLOR } },
    { 5353, { "MDNS", ANSI_RGB(0,255,174) } }
};


// This function may be called only when a protocol wants to modify both the color and alternate protocol name
// Otherwise, its enough to only get the color with ColorPicker
protocol_properties ProtocolDeterminer::get_protocol_properties_by_type(const PDU::PDUType type, const uint16_t id)
{
    std::map<uint16_t, protocol_properties> chosenMap;

    switch (type)
    {
    case PDU::PDUType::ETHERNET_II:
        chosenMap = _eth2_types;
        break;

    case PDU::PDUType::IP:
        chosenMap = _ip_protocols;
        break;
    
    default:
        return NULL_PROPERTIES;
    }

    const auto typeIterator = chosenMap.find(id);
    return (typeIterator != chosenMap.end()) ? typeIterator->second : NULL_PROPERTIES;
}

bool ProtocolDeterminer::does_alt_protocol_exist_for_port(const uint16_t port)
{
    return (_port_protocols.find(port) != _port_protocols.end());
}

protocol_properties ProtocolDeterminer::get_protocol_properties_by_ports(const uint16_t sport, const uint16_t dport)
{
    if (does_alt_protocol_exist_for_port(sport))
    {
        return _port_protocols.find(sport)->second;
    }
    else if (does_alt_protocol_exist_for_port(dport))
    {
        return _port_protocols.find(dport)->second;
    }
    return NULL_PROPERTIES;
}
