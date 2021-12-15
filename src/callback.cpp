#include "callback.h"

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

        PacketPrinter::protocol_switch(innerType, inner, nextInnerPDU);

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
