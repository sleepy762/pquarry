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
}

NetscoutServer::~NetscoutServer()
{
    close(this->_client_sockfd);
    close(this->_server_sockfd);
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
    while (true)
    {
        this->accept();
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
    std::string filters = this->get_filters_from_client();
    this->start_sniffer(interface, filters);
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
