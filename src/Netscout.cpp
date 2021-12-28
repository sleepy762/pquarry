#include "Netscout.h"

std::list<PDU*> _savedPDUs;

Netscout::Netscout() 
{
    this->_interface = "";
    this->_filters = "";
}

Netscout::~Netscout() 
{
    // Free savedPDUs
}

bool Netscout::callback(const PDU& pdu)
{
    // Initial packet number
    static int packetNumber = 1;
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Holds the packet output line
    std::stringstream ss;
    // Packet serial number
    ss << packetNumber << "\t";

    protocol_properties properties;

    PDU* originalPDU = pdu.clone();
    // Gather data from all the protocols in the list of PDUs
    PDU* inner = originalPDU;
    while (inner != nullptr)
    {
        PDU::PDUType innerType = inner->pdu_type();

        // Store the sequence of protocols
        if (innerType != pdu.RAW)
        {
            properties = PacketPrinter::get_protocol_properties(innerType, inner, ss);
            protocols.push_back(innerType);
        }

        // Advance the pdu list
        inner = inner->inner_pdu();
    }
    ss << originalPDU->size() << "\t";

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

    _savedPDUs.push_back(originalPDU);
    packetNumber++;
    return true;
}

void Netscout::start_sniffer() const
{
    try
    {
        Sniffer(this->_interface).sniff_loop(callback);
    }
    catch(const std::exception& e)
    {
        NetscoutMenu::print_error_msg(e.what());
    }
}

void Netscout::menu_loop()
{
    int choice;

    do
    {
        NetscoutMenu::main_menu();
        choice = NetscoutMenu::get_int();

        switch (choice)
        {
        case START_SNIFFER_OPT:
            std::cout << "Starting sniffer on interface " << this->_interface << '\n';
            this->start_sniffer();
            break;

        case SET_INTERFACE_OPT:
        {
            std::string newInterface;

            std::cout << "Current interface: " << this->_interface << '\n';
            std::cout << "Enter interface: ";

            std::getline(std::cin, newInterface);
            this->set_interface(newInterface);

            NetscoutMenu::print_success_msg("New interface has been set.");
            break;
        }

        case SET_FILTERS_OPT:
        {
            std::string newFilters;

            std::cout << "Current filters: " << this->get_filters() << '\n';
            std::cout << "Enter filters: "; // Temporary, there will be an interactive menu

            std::getline(std::cin, newFilters);
            this->set_filters(newFilters);

            NetscoutMenu::print_success_msg("New filters have been set.");
            break;
        }

        case EXIT_OPT:
            break;

        default:
            NetscoutMenu::print_error_msg("Invalid option.");
            break;
        }
    } while (choice != EXIT_OPT);
}

std::string Netscout::get_interface() const
{
    return this->_interface;
}

void Netscout::set_interface(std::string interface)
{
    this->_interface = interface;
}

std::string Netscout::get_filters() const
{
    return this->_filters;
}

void Netscout::set_filters(std::string filters)
{
    this->_filters = filters;
}
