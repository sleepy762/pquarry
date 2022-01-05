#include "NetscoutServer.h"

NetscoutServer::NetscoutServer(std::string ip, uint16_t port)
{
    this->_ip_address = ip;
    this->_port = port;

    this->_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->_server_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Invalid socket.");
    }
    this->acquire_interfaces();
}

NetscoutServer::~NetscoutServer()
{
    close(this->_client_sockfd);
    close(this->_server_sockfd);
}

void NetscoutServer::acquire_interfaces()
{
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
        throw std::runtime_error("Binding failed.");
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
    this->_client_sockfd = ::accept(this->_server_sockfd, nullptr, nullptr);

    if (this->_client_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Accepted invalid socket.");
    }

    std::cout << "Client connected." << '\n';
    // Get necessary info from the client 
    std::string interface = this->get_interface_from_client();
    std::cout << interface;
    //std::string filters = this->get_filters_from_client();
    //this->start_sniffer(interface, filters);
}

std::string NetscoutServer::get_interface_from_client() const
{
    bool valid;
    std::string interface;
    std::string fmt_msg = this->get_formatted_interfaces_msg();

    // Send the initial message
    Communicator::send(this->_client_sockfd, fmt_msg);
    do
    {
        interface = Communicator::recv(this->_client_sockfd);
        valid = this->is_interface_valid(interface);

        if (!valid)
        {
            Communicator::send(this->_client_sockfd, "Invalid interface.\n");
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
        msg += '\n';
    }

    return msg;
}

bool NetscoutServer::is_interface_valid(std::string& interface) const
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

void NetscoutServer::start_sniffer(const std::string& interface, const std::string& filters)
{
    SnifferConfiguration config;
    config.set_filter(filters);
    config.set_immediate_mode(true);
    
    Sniffer sniffer = Sniffer(interface, config);
    sniffer.set_extract_raw_pdus(true); // Don't interpret packets
    sniffer.sniff_loop(callback);
}

bool NetscoutServer::callback(const Packet& packet)
{
    return true;
}
