#include "NetscoutMenu.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include "Version.h"
#include "RemoteSniffer.h"
#include "LocalSniffer.h"
#include "PacketPrinter.h"

#define ERROR_COLOR (ANSI_RGB(217,35,35))
#define SUCCESS_COLOR (ANSI_RGB(35,217,83))

#define PCAP_FILE_EXTENSION (".pcap")

const std::map<menu_entry_index, const char*> NetscoutMenu::_main_menu_entries = 
{
    { START_LOCAL_SNIFFER_OPT, "Start sniffer" },
    { START_REMOTE_SNIFFER_OPT, "Connect to remote sniffer" },
    { SET_INTERFACE_OPT, "Set interface" },
    { SET_FILTERS_OPT, "Set pcap filters" },
    { EXPORT_PACKETS_OPT, "Export packets into pcap" },
    { CLEAR_SAVED_PACKETS_OPT, "Clear saved packets"},
    { SEE_INFO_OPT, "See information" },
    { EXIT_OPT, "Exit" }
};

NetscoutMenu::NetscoutMenu(PacketContainer& packet_container)
    : _packet_container(packet_container)
{
    this->_local_interface = "";
    this->_local_filters = "";
}

NetscoutMenu::~NetscoutMenu() {}

NetscoutMenu::NetscoutMenu(PacketContainer& packet_container, int argc, char** argv)
    : _packet_container(packet_container)
{
    // If arguments were passed, we use the 2nd arg as the interface and the 3rd+ as the filters
    if (argc >= 2)
    {
        this->_local_interface = argv[1];
        if (argc >= 3)
        {
            // Concatenate the rest of the arguments into filters (starts at argv[2])
            // Alternatively, the user can simply put the filters in quotes
            for (int i = 2; i < argc; i++)
            {
                this->_local_filters += argv[i];
                if (i + 1 != argc) // Add spaces in between args
                {
                    this->_local_filters += ' ';
                }
            }
        }
    }
    else
    {
        this->_local_interface = "";
        this->_local_filters = "";
    }
}

void NetscoutMenu::print_success_msg(const char* msg)
{
    std::cout << SUCCESS_COLOR << msg << RESET_COLOR << '\n';
}

void NetscoutMenu::print_error_msg(const char* msg)
{
    std::cerr << ERROR_COLOR << msg << RESET_COLOR << '\n';
}

void NetscoutMenu::print_main_menu() const
{
    std::cout << '\n' << "NetScout Version " << CLIENT_VERSION << '\n';
    for (auto it = _main_menu_entries.cbegin(); it != _main_menu_entries.cend(); it++)
    {
        std::cout << '[' << it->first << ']' << ' ' << it->second << '\n';
    }
    std::cout << "Select an option: ";
}

std::vector<interface_ip_pair> NetscoutMenu::get_interface_list() const
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

void NetscoutMenu::menu_loop()
{
    int32_t choice;
    do
    {
        this->print_main_menu();
        choice = NetscoutMenu::get_value<int32_t>();
        std::cout << '\n';
        try
        {
            switch (choice)
            {
            case START_LOCAL_SNIFFER_OPT:
                this->start_local_sniffer();
                break;

            case START_REMOTE_SNIFFER_OPT:
                this->start_remote_sniffer();
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
                this->clear_saved_packets();
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

void NetscoutMenu::clear_saved_packets() const
{
    size_t amountOfPackets = this->_packet_container.size();

    // The clear() method calls the destructor for each packet
    this->_packet_container.clear_packets();
    PacketPrinter::reset_packet_number();

    const std::string msg = std::to_string(amountOfPackets) + " saved packets were cleared.";
    NetscoutMenu::print_success_msg(msg.c_str());
}

void NetscoutMenu::export_packets() const
{
    if (this->_packet_container.size() == 0)
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
        || filename.substr(filenameLength - extensionLength) != PCAP_FILE_EXTENSION)
    {
        filename += PCAP_FILE_EXTENSION;
    }

    // Writes the packets into a pcap file
    PacketWriter writer(filename, DataLinkType<EthernetII>());
    const std::list<Packet>& packet_list = this->_packet_container.get_packet_list();
    for (auto it = packet_list.begin(); it != packet_list.end(); it++)
    {
        Packet packet = *it;
        writer.write(packet);
    }

    const std::string msg = std::to_string(packet_list.size()) + " packets were written to " + filename;
    NetscoutMenu::print_success_msg(msg.c_str());
}

void NetscoutMenu::see_information() const
{
    std::cout << "== Information ==" << '\n';
    std::cout << "Interface: " << this->_local_interface << '\n';
    std::cout << "Filters: " << this->_local_filters << '\n';
    std::cout << "Saved packets: " << this->_packet_container.size() << '\n';
    std::cout << "Packet limit: " << MAX_AMOUNT_OF_PACKETS << '\n';
}

void NetscoutMenu::set_interface()
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

void NetscoutMenu::set_interface(std::string interface)
{
    this->_local_interface = interface;
}

void NetscoutMenu::set_filters()
{
    std::string newFilters = "";

    std::cout << "Current pcap filters: " << this->_local_filters << '\n';
    std::cout << "Enter new pcap filters: ";

    std::getline(std::cin, newFilters);
    this->set_filters(newFilters);

    NetscoutMenu::print_success_msg("New filters have been set.");
}

void NetscoutMenu::set_filters(std::string filters)
{
    this->_local_filters = filters;
}

void NetscoutMenu::start_local_sniffer() const
{
    LocalSniffer lsniffer(this->_packet_container, this->_local_interface, this->_local_filters);
    lsniffer.start_sniffer();
}

void NetscoutMenu::start_remote_sniffer() const
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

    RemoteSniffer rsniffer(this->_packet_container, ip, port);
    rsniffer.start_sniffer();
}
