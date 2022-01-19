#include "NetscoutServer.h"

int32_t NetscoutServer::_client_sockfd = INVALID_SOCKET;

NetscoutServer::NetscoutServer(uint16_t port)
{
    this->_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->_server_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Failed to create socket.");
    }

    this->_port = port;
}

NetscoutServer::~NetscoutServer()
{
    if (_client_sockfd != INVALID_SOCKET)
    {
        close(_client_sockfd);
    }
    close(this->_server_sockfd);
}

void NetscoutServer::update_interface_list()
{
    this->_avail_interfaces.clear();

    char buf[1024];
    struct ifconf ifc;
    struct ifreq* ifr;
    int32_t num_interfaces;

    // Querying the available interfaces
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(this->_server_sockfd, SIOCGIFCONF, &ifc) < 0)
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

        this->_avail_interfaces.push_back(interface_ip_pair(interface, ip));
    }
}

void NetscoutServer::start()
{
    struct sockaddr_in sock_addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    sock_addr.sin_port = htons(this->_port);

    if (bind(this->_server_sockfd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0)
    {
        throw std::runtime_error("Binding failed. (Try using a different port)");
    }
    if (listen(this->_server_sockfd, 0) < 0)
    {
        throw std::runtime_error("Error while setting up listener.");
    }

    std::cout << "Listening on port " << this->_port << '\n';
    // Accept connections until server is closed
    while (true)
    {
        try
        {
            this->accept();
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
    }
}

void NetscoutServer::accept()
{
    struct sockaddr_in client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

    _client_sockfd = ::accept(this->_server_sockfd, (struct sockaddr*)&client_addr, &client_addrlen);
    if (_client_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Accepted invalid socket.");
    }

    // Get the connected client's ip address and port
    char client_ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_address, sizeof(client_ip_address));
    uint16_t client_port = ntohs(client_addr.sin_port);

    std::cout << "Client connected at " << client_ip_address << ":" << client_port << '\n';
    this->update_interface_list();
    this->configure_sniffer_with_client();
    this->start_sniffer();
}

void NetscoutServer::configure_sniffer_with_client()
{
    // Get the necessary info from the client 
    this->_chosen_interface = this->get_interface_from_client();
    this->_chosen_filters = this->get_filters_from_client();

    // We should ignore our own traffic
    // This filter removes traffic on the port which we are working with
    if (this->_chosen_filters != "")
    {
        this->_chosen_filters += " and ";
    }
    this->_chosen_filters += "not port " + std::to_string(this->_port);

    Communicator::send(_client_sockfd, "Configuration complete!");
}

std::string NetscoutServer::get_interface_from_client() const
{
    bool valid;
    std::string interface;
    std::string fmt_msg = this->get_formatted_interfaces_msg();

    // Send the initial message
    Communicator::send(_client_sockfd, fmt_msg);
    do
    {
        interface = Communicator::recv(_client_sockfd);
        valid = this->is_interface_valid(interface);

        if (!valid)
        {
            Communicator::send(_client_sockfd, "Invalid interface.");
        }
    } while (!valid);
    
    return interface;
}

std::string NetscoutServer::get_formatted_interfaces_msg() const
{
    std::string msg;

    msg += "Please choose an interface to analyze:\n";
    for (auto it = _avail_interfaces.cbegin(); it != _avail_interfaces.cend(); it++)
    {
        msg += it->first;
        msg += " : IP ";
        msg += it->second;
        // Add a newline if its not the last interface
        if (it + 1 != _avail_interfaces.cend())
        {
            msg += '\n';
        }
    }

    return msg;
}

bool NetscoutServer::is_interface_valid(const std::string& interface) const
{
    for (auto it = _avail_interfaces.cbegin(); it != _avail_interfaces.cend(); it++)
    {
        // The interface is available and valid
        if (it->first == interface)
        {
            return true;
        }
    }
    return false;
}

std::string NetscoutServer::get_filters_from_client() const
{
    bool valid;
    std::string filters = "";
    std::string fmt_msg = "Enter pcap filters (write 'no' for no filters)";

    Communicator::send(_client_sockfd, fmt_msg);
    do
    {
        std::string filter_error = "";

        filters = Communicator::recv(_client_sockfd);

        CapabilitySetter::set_required_caps();
        valid = this->are_filters_valid(filters, filter_error);
        CapabilitySetter::clear_required_caps();

        if (!valid)
        {
            std::string msg = "Invalid filters: " + filter_error;
            Communicator::send(_client_sockfd, msg);
        }
    } while (!valid);
    
    return filters;
}

bool NetscoutServer::are_filters_valid(std::string& filters, std::string& error_out) const
{
    // It's impossible to send an empty string and recv it, so we must use some special string
    // It's also important to clear the special string from the filters because it's not valid
    if (filters == NO_FILTERS_STR)
    {
        filters = "";
        return true;
    }

    // Check if the filters are valid
    try
    {
        SnifferConfiguration config;
        config.set_filter(filters);
        Sniffer tempSniffer = Sniffer(this->_chosen_interface, config);
    }
    catch(const std::exception& e)
    {
        error_out = e.what();
        return false;
    }
    return true;
}

void NetscoutServer::start_sniffer()
{
    SnifferConfiguration config;
    config.set_filter(this->_chosen_filters);
    config.set_immediate_mode(true);

    CapabilitySetter::set_required_caps();

    Sniffer sniffer = Sniffer(this->_chosen_interface, config);
    sniffer.set_extract_raw_pdus(true); // Don't interpret packets
    sniffer.sniff_loop(callback);
    
    CapabilitySetter::clear_required_caps();
}

bool NetscoutServer::callback(const Packet& packet)
{
    std::unique_ptr<PDU> pdu(packet.pdu()->clone());
    byte_array bytes = pdu->serialize();

    std::string bytes_string = Serializer::serialize_data(bytes);
    try
    {
        Communicator::send(_client_sockfd, bytes_string);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return false; // Stop the sniffer
    }

    return true;
}