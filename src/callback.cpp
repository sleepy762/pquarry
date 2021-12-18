#include "callback.h"

std::list<PDU*> savedPDUs;

bool callback(const PDU& pdu)
{
    // Initial packet number
    static int packetNumber = 1;
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Holds the packet output line
    std::stringstream ss;
    // Packet serial number
    ss << packetNumber << "\t";

    std::string altProtocolName = "";
    const char* colorPtr = nullptr;

    PDU* originalPDU = pdu.clone();
    // Gather data from all the protocols in the list of PDUs
    PDU* inner = originalPDU;
    while (inner != nullptr)
    {
        PDU::PDUType innerType = inner->pdu_type();
        PDU* nextInnerPDU = inner->inner_pdu();

        // Store the sequence of protocols
        if (innerType != pdu.RAW)
        {
            colorPtr = PacketPrinter::protocol_switch(innerType, inner, nextInnerPDU, ss, altProtocolName);
            protocols.push_back(innerType);
        }

        // Advance the pdu list
        inner = nextInnerPDU;
    }
    ss << originalPDU->size() << "\t";

    // Append alternative protocol name, if it exists
    if (altProtocolName != "")
    {
        ss << altProtocolName << '(' << Utils::to_string(protocols.back()) << ')';
    }
    else
    {
        ss << Utils::to_string(protocols.back());
    }

    // Output the entire packet string stream
    std::cout << colorPtr << ss.str() << RESET_COLOR << '\n';

    savedPDUs.push_back(originalPDU);
    packetNumber++;
    return true;
}
