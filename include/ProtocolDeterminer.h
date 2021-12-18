#pragma once
#include <tins/tins.h>
#include <map>

using namespace Tins;

class ProtocolDeterminer
{
    static const std::map<uint8_t, const char*> _llc_mod_funcs;
    static const std::map<uint16_t, const char*> _eth2_types;
    static const std::map<uint8_t, const char*> _ip_protocols;
    static const std::map<uint16_t, const char*> _port_protocols;

public:
    static const char* llc_modifier_func_string(uint8_t modfunc);
    static const char* eth2_type_string(uint16_t type);
    static const char* ip_protocol_string(uint8_t protocol);
    static const char* port_protocol_string(uint16_t port);
    static bool check_if_alt_protocol_exists(uint16_t port);
};
