#pragma once
#include <tins/tins.h>
#include <map>

#define ANSI_RGB(r, g, b) ("\033[38;2;"#r";"#g";"#b"m")
#define RESET_COLOR ("\033[0m")

#define DEFAULT_COLOR (ANSI_RGB(255,255,255))

using namespace Tins;

typedef struct protocol_properties
{
    const char* protocolString;
    const char* protocolColor;
} protocol_properties;

extern const protocol_properties NULL_PROPERTIES;

class ProtocolDeterminer
{
private:
    static const std::map<uint16_t, protocol_properties> _eth2_types;
    static const std::map<uint16_t, protocol_properties> _ip_protocols;
    static const std::map<uint16_t, protocol_properties> _port_protocols;

public:
    static protocol_properties get_protocol_properties_by_type(const PDU::PDUType type, const uint16_t id);

    static bool does_alt_protocol_exist_for_port(const uint16_t port);
    static protocol_properties get_protocol_properties_by_ports(const uint16_t sport, const uint16_t dport);

    static const char* get_color_by_pdu_type(const PDU::PDUType type);
};
