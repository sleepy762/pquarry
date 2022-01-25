#include "LocalSniffer.h"

std::list<Packet> LocalSniffer::_saved_packets;
Sniffer* LocalSniffer::_sniffer = nullptr;
uint32_t LocalSniffer::_packet_number = 1;

LocalSniffer::LocalSniffer() 
{
    this->_local_interface = "";
    this->_local_filters = "";
}

LocalSniffer::LocalSniffer(std::string interface, std::string filters)
{
    this->_local_interface = interface;
    this->_local_filters = filters;
}

LocalSniffer::~LocalSniffer() 
{
    this->clear_saved_packets();
}

LocalSniffer LocalSniffer::instantiate_with_args(int argc, char** argv)
{
    std::string interface = "";
    std::string filters = "";

    // If arguments were passed, we use the 2nd arg as the interface and the 3rd+ as the filters
    if (argc >= 2)
    {
        interface = argv[1];
        if (argc >= 3)
        {
            // Concatenate the rest of the arguments into filters (starts at argv[2])
            // Alternatively, the user can simply put the filters in quotes
            for (int i = 2; i < argc; i++)
            {
                filters += argv[i];
                if (i + 1 != argc) // Add spaces in between args
                {
                    filters += ' ';
                }
            }
        }
    }
    return LocalSniffer(interface, filters);
}

std::vector<interface_ip_pair> LocalSniffer::get_interface_list() const
{
    char buf[1024];
    struct ifconf ifc;
    struct ifreq* ifr;
    int32_t num_interfaces;
    std::vector<interface_ip_pair> interface_vec;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Querying the available interfaces
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
    {
        throw std::runtime_error("Call to ioctl failed.");
    }

    // Iterating the interfaces and adding the IP address too
    ifr = ifc.ifc_req;
    num_interfaces = ifc.ifc_len / sizeof(struct ifreq);
    for (int i = 0; i < num_interfaces; i++)
    {
        struct ifreq* item = &ifr[i];
        
        std::string interface = item->ifr_name;
        std::string ip = inet_ntoa(((struct sockaddr_in*)&item->ifr_addr)->sin_addr);

        interface_vec.push_back(interface_ip_pair(interface, ip));
    }
    return interface_vec;
}

void LocalSniffer::menu_loop()
{
    int choice;
    do
    {
        NetscoutMenu::main_menu();
        choice = NetscoutMenu::get_value<int32_t>();
        std::cout << '\n';
        try
        {
            switch (choice)
            {
            case START_SNIFFER_OPT:
                this->start_sniffer();
                break;

            case CONNECT_TO_REMOTE_SNIFFER_OPT:
                this->connect_to_remote_sniffer();
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
                throw std::runtime_error("Invalid option.");
                break;
            }
        }
        catch (const std::exception& e)
        {
            NetscoutMenu::print_error_msg(e.what());
        }
    } while (choice != EXIT_OPT);
}

bool LocalSniffer::callback(const Packet& packet)
{
    // Stores a list of the protocols in the PDU in order
    std::list<PDU::PDUType> protocols;

    // Holds the packet output line
    std::stringstream ss;
    // Packet serial number
    ss << _packet_number << '\t';

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
    _saved_packets.push_back(Packet(packet));
    _packet_number++;
    return true;
}

// Stops the sniffer when Ctrl-C is pressed
void LocalSniffer::sniffer_interrupt(int)
{
    if (_sniffer != nullptr)
    {
        _sniffer->stop_sniff();

        delete _sniffer;
        _sniffer = nullptr;
    }
    // We want to disable the signal handler when we are not sniffing
    SignalHandler::set_signal_handler(SIGINT, SIG_DFL, 0);
}

void LocalSniffer::start_sniffer()
{
    // Failsafe
    if (_sniffer != nullptr)
    {
        delete _sniffer;
    }
    // Check if no interface was set
    if (this->_local_interface == "")
    {
        throw std::runtime_error("You must set an interface.");
    }

    std::cout << "Starting sniffer on interface " << this->get_interface() << '\n';

    // Instantiate the config to add our pcap filters
    SnifferConfiguration config;
    config.set_filter(this->get_filters());
    config.set_immediate_mode(true);

    CapabilitySetter::set_required_caps();
    // The sniffer is allocated on the heap because we want to access the object in a separate function
    // see LocalSniffer::sniffer_interrupt
    _sniffer = new Sniffer(this->_local_interface, config);

    // We want the signal handler to work only while sniffing
    SignalHandler::set_signal_handler(SIGINT, LocalSniffer::sniffer_interrupt, 0);

    // Starts the sniffer
    _sniffer->sniff_loop(callback);
    
    CapabilitySetter::clear_required_caps();
}

void LocalSniffer::connect_to_remote_sniffer()
{
    std::string ip = "";
    uint16_t port;

    std::cout << "Enter the IP address of the server: ";
    std::getline(std::cin, ip);

    if (ip == "")
    {
        throw std::runtime_error("Aborting connection because the IP address is empty.");
    }

    std::cout << "Enter the server port: ";
    port = NetscoutMenu::get_value<uint16_t>();
    std::cout << '\n';

    RemoteSniffer rsniffer = RemoteSniffer(ip, port);
    rsniffer.start();
}

void LocalSniffer::clear_saved_packets()
{
    int amountOfPackets = _saved_packets.size();

    _saved_packets.clear();
    _packet_number = 1;

    const std::string msg = std::to_string(amountOfPackets) + " saved packets were cleared.";
    NetscoutMenu::print_success_msg(msg.c_str());
}

void LocalSniffer::export_packets() const
{
    if (_saved_packets.size() == 0)
    {
        throw std::runtime_error("There are no saved packets.");
    }

    std::string filename = "";
    std::cout << "Enter pcap filename(or full path): ";
    std::getline(std::cin, filename);

    if (filename == "")
    {
        throw std::runtime_error("Aborting export because filename is empty.");
    }

    // Append ".pcap" to the end of the filename if the user hasn't done it
    // If the filename is shorter than the extension, also append the extension
    size_t filenameLength = filename.length();
    size_t extensionLength = std::string(PCAP_FILE_EXTENSION).length();
    if (filenameLength < extensionLength
        || (filenameLength > extensionLength 
        && filename.substr(filenameLength - extensionLength) != PCAP_FILE_EXTENSION))
    {
        filename += PCAP_FILE_EXTENSION;
    }

    // Temporary workaround with capabilities
    if (geteuid() == 0) CapabilitySetter::set_required_caps();
    // Writes the packets into a pcap file
    PacketWriter writer(filename, DataLinkType<EthernetII>());
    for (auto it = _saved_packets.begin(); it != _saved_packets.end(); it++)
    {
        writer.write(*it);
    }
    if (geteuid() == 0) CapabilitySetter::clear_required_caps();

    const std::string msg = std::to_string(_saved_packets.size()) + " packets were written to " + filename;
    NetscoutMenu::print_success_msg(msg.c_str());
}

void LocalSniffer::see_information() const
{
    std::cout << "== Information ==" << '\n';
    std::cout << "Interface: " << this->get_interface() << '\n';
    std::cout << "Filters: " << this->get_filters() << '\n';
    std::cout << "Saved packets: " << _saved_packets.size() << '\n';
}

std::string LocalSniffer::get_interface() const
{
    return this->_local_interface;
}

void LocalSniffer::set_interface()
{
    std::string newInterface = "";
    const std::vector<interface_ip_pair> interfaces = this->get_interface_list();

    // Print all the available interfaces for convenience
    std::cout << "Available interfaces: " << '\n';
    for (auto it = interfaces.cbegin(); it != interfaces.cend(); it++)
    {
        std::cout << it->first << " : IP " << it->second << '\n';
    }
    std::cout << '\n';

    std::cout << "Current interface: " << this->_local_interface << '\n';
    std::cout << "Enter new interface: ";

    std::getline(std::cin, newInterface);
    this->set_interface(newInterface);

    NetscoutMenu::print_success_msg("New interface has been set."); 
}

void LocalSniffer::set_interface(std::string interface)
{
    this->_local_interface = interface;
}

std::string LocalSniffer::get_filters() const
{
    return this->_local_filters;
}

void LocalSniffer::set_filters()
{
    std::string newFilters = "";

    std::cout << "Current pcap filters: " << this->get_filters() << '\n';
    std::cout << "Enter new pcap filters: ";

    std::getline(std::cin, newFilters);
    this->set_filters(newFilters);

    NetscoutMenu::print_success_msg("New filters have been set.");
}

void LocalSniffer::set_filters(std::string filters)
{
    this->_local_filters = filters;
}
