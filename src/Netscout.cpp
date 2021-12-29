#include "Netscout.h"

std::list<PDU*> Netscout::_savedPDUs;
Sniffer* Netscout::_sniffer = nullptr;
unsigned int Netscout::_packet_number = 1;

Netscout::Netscout() 
{
    this->_interface = "";
    this->_filters = "";
}

Netscout::~Netscout() 
{
    // Free all dynamically allocated memory
    this->clear_saved_packets();
}

bool Netscout::callback(const PDU& pdu)
{
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Holds the packet output line
    std::stringstream ss;
    // Packet serial number
    ss << _packet_number << "\t";

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
    _packet_number++;
    return true;
}

// Stops the sniffer when Ctrl-C is pressed
void Netscout::sniffer_interrupt(int)
{
    if (_sniffer != nullptr)
    {
        _sniffer->stop_sniff();

        delete _sniffer;
        _sniffer = nullptr;
    }
    // We want to disable the signal handler when we are not sniffing
    signal(SIGINT, SIG_DFL);
}

void Netscout::start_sniffer()
{
    // Failsafe
    if (_sniffer != nullptr)
    {
        delete _sniffer;
    }

    std::cout << "Starting sniffer on interface " << this->get_interface() << '\n';
    try
    {
        // Instantiate the config to add our pcap filters
        SnifferConfiguration config;
        config.set_filter(this->get_filters());

        // The sniffer is allocated on the heap because we want to access the object in a separate function
        // see Netscout::sniffer_interrupt
        _sniffer = new Sniffer(this->_interface, config);

        // We want the signal handler to work only while sniffing
        signal(SIGINT, Netscout::sniffer_interrupt);

        // Starts the sniffer
        _sniffer->sniff_loop(callback);
    }
    catch(const std::exception& e)
    {
        NetscoutMenu::print_error_msg(e.what());
    }
    std::cout << '\n' << "Sniffed " << _savedPDUs.size() << " packets so far." << '\n';
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
            this->start_sniffer();
            break;

        case SET_INTERFACE_OPT:
            this->set_interface();
            break;

        case SET_FILTERS_OPT:
            this->set_filters();
            break;

        case EXPORT_PACKETS_OPT:
            this->export_packets();
            break;

        case CLEAR_SAVED_PACKETS_OPT:
            this->clear_saved_packets();
            break;

        case SEE_INFO_OPT:
            this->see_information();
            break;
    
        case EXIT_OPT:
            break;

        default:
            NetscoutMenu::print_error_msg("Invalid option.");
            break;
        }
    } while (choice != EXIT_OPT);
}

void Netscout::clear_saved_packets()
{
    int amountOfPackets = _savedPDUs.size();

    // the PDUs were allocated on the heap and it's our responsibility to delete them
    for (auto it = _savedPDUs.begin(); it != _savedPDUs.end(); it++)
    {
        delete *it;
    }
    _savedPDUs.clear();
    _packet_number = 1;

    const std::string msg = std::to_string(amountOfPackets) + " saved packets were cleared.";
    NetscoutMenu::print_success_msg(msg.c_str());
}

void Netscout::export_packets() const
{
    if (_savedPDUs.size() == 0)
    {
        NetscoutMenu::print_error_msg("There are no saved packets.");
        return;
    }

    std::string filename = "";
    std::cout << "Enter pcap filename(or full path): ";
    std::getline(std::cin, filename);

    if (filename == "")
    {
        NetscoutMenu::print_error_msg("Aborting export because filename is empty.");
        return;
    }

    filename += ".pcap";

    // Writes the packets into a pcap file
    PacketWriter writer(filename, DataLinkType<EthernetII>());
    writer.write(_savedPDUs.cbegin(), _savedPDUs.cend());

    const std::string msg = std::to_string(_savedPDUs.size()) + " packets were written to " + filename;
    NetscoutMenu::print_success_msg(msg.c_str());
}

void Netscout::see_information() const
{
    std::cout << '\n' << "== Information ==" << '\n';
    std::cout << "Interface: " << this->get_interface() << '\n';
    std::cout << "Filters: " << this->get_filters() << '\n';
    std::cout << "Saved packets: " << _savedPDUs.size() << '\n';
}

std::string Netscout::get_interface() const
{
    return this->_interface;
}

void Netscout::set_interface()
{
    std::string newInterface = "";

    std::cout << "Current interface: " << this->_interface << '\n';
    std::cout << "Enter new interface: ";

    std::getline(std::cin, newInterface);
    this->set_interface(newInterface);

    NetscoutMenu::print_success_msg("New interface has been set."); 
}

void Netscout::set_interface(std::string interface)
{
    this->_interface = interface;
}

std::string Netscout::get_filters() const
{
    return this->_filters;
}

void Netscout::set_filters()
{
    std::string newFilters = "";

    std::cout << "Current pcap filters: " << this->get_filters() << '\n';
    std::cout << "Enter new pcap filters: ";

    std::getline(std::cin, newFilters);
    this->set_filters(newFilters);

    NetscoutMenu::print_success_msg("New filters have been set.");
}

void Netscout::set_filters(std::string filters)
{
    this->_filters = filters;
}
