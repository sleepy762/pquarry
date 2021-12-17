#include "ProtocolDeterminer.h"

const std::map<uint8_t, const char*> ProtocolDeterminer::_llc_mod_funcs = 
{
    { LLC::ModifierFunctions::UI, "UI" },
    { LLC::ModifierFunctions::DISC, "DISC" },
    { LLC::ModifierFunctions::UA, "UA" },
    { LLC::ModifierFunctions::TEST, "TEST" },
    { LLC::ModifierFunctions::FRMR, "FRMR" },
    { LLC::ModifierFunctions::DM, "DM" },
    { LLC::ModifierFunctions::XID, "XID" },
    { LLC::ModifierFunctions::SABME, "SABME" }
};

const std::map<uint16_t, const char*> ProtocolDeterminer::_eth2_types =
{
    { 0x88cc, "LLDP" },
    { 0x893a, "ieee1905" }
};

const std::map<uint8_t, const char*> ProtocolDeterminer::_ip_protocols = 
{
    { 0x02, "IGMP" }
};

// This includes both UDP and TCP ports, which may cause incorrect determinations
const std::map<uint16_t, const char*> ProtocolDeterminer::_port_protocols =
{
    { 20, "FTP" },
    { 21, "FTP" },
    { 22, "SSH" },
    { 23, "Telnet" },
    { 25, "SMTP" },
    { 50, "IPSec" },
    { 51, "IPSec" },
    { 53, "DNS" },
    { 67, "DHCP" },
    { 68, "DHCP" },
    { 69, "TFTP" },
    { 80, "HTTP" },
    { 110, "POP3" },
    { 119, "NNTP" },
    { 123, "NTP" },
    { 137, "NBNS" },
    { 138, "NBDS" },
    { 139, "NBSS" },
    { 143, "IMAP4" },
    { 161, "SNMP" },
    { 162, "SNMP" },
    { 389, "LDAP" },
    { 443, "HTTPS" },
    { 989, "FTPS" },
    { 990, "FTPS" },
    { 3389, "RDP" }
};


const char* ProtocolDeterminer::llc_modifier_func_string(uint8_t modfunc)
{
    auto funcStr = ProtocolDeterminer::_llc_mod_funcs.find(modfunc);
    return funcStr != ProtocolDeterminer::_llc_mod_funcs.end() ? funcStr->second : "";
}

const char* ProtocolDeterminer::eth2_type_string(uint16_t type)
{
    auto eth2Type = ProtocolDeterminer::_eth2_types.find(type);
    return eth2Type != ProtocolDeterminer::_eth2_types.end() ? eth2Type->second : "";
}

const char* ProtocolDeterminer::ip_protocol_string(uint8_t protocol)
{
    auto ipProto = ProtocolDeterminer::_ip_protocols.find(protocol);
    return ipProto != ProtocolDeterminer::_ip_protocols.end() ? ipProto->second : "";
}

const char* ProtocolDeterminer::port_protocol_string(uint16_t port)
{
    auto portProto = ProtocolDeterminer::_port_protocols.find(port);
    return portProto != ProtocolDeterminer::_port_protocols.end() ? portProto->second : "";
}
