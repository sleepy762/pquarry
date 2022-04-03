#include "callback.h"
#include <sstream>
#include "ProtocolDeterminer.h"
#include "PacketPrinter.h"
#include <iostream>

std::list<Packet> saved_packets;
uint64_t packet_number = 1;

bool callback(const Packet& packet)
{
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Holds the packet output line
    std::stringstream ss;
    // Packet serial number
    ss << packet_number << '\t';

    protocol_properties properties;

    std::unique_ptr<PDU> originalPDU(packet.pdu()->clone());
    // Gather data from all the protocols in the list of PDUs
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

    // Saving a copy of the packet while maintaining const correctness
    saved_packets.push_back(Packet(packet));
    packet_number++;
    return true;
}
