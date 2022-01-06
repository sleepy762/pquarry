#include "RemoteSniffer.h"

RemoteSniffer::RemoteSniffer(std::string ip, uint16_t port)
{
    this->_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->_server_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Failed to create socket.");
    }
    this->_ip = ip;
    this->_port = port;

    this->_connect_succeeded = false;
    this->_sniffer_configured = false;
}

RemoteSniffer::~RemoteSniffer()
{
    close(this->_server_sockfd);
}

void RemoteSniffer::connect()
{
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(this->_port);

    if (inet_pton(AF_INET, this->_ip.c_str(), &serv_addr.sin_addr) <= 0)
    {
        throw std::runtime_error("Invalid address.");
    }
    if (::connect(this->_server_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        throw std::runtime_error("Connection failed.");
    }
    this->_connect_succeeded = true;
}

void RemoteSniffer::configure_sniffer()
{
    if (this->_connect_succeeded == false)
    {
        throw std::runtime_error("RemoteSniffer::connect() wasn't called.");
    }

    bool configuration_finished = false;
    // "interface_selected" acts as a switch for setting both the interface and filters members of this class
    // while it's false, the interface is being set, when it becomes true, the filters will be set
    bool interface_selected = false;
    std::string response = "";
    while (!configuration_finished)
    {
        std::string server_msg = Communicator::recv(this->_server_sockfd);
        std::cout << server_msg << '\n';

        // Check if the substring "Invalid" is in the server_msg
        // ideally I should make a protocol for this server to client communication (later)
        if (server_msg.substr(0, server_msg.find(' ')) != INVALID_SUBSTR && response != "")
        {
            switch (interface_selected)
            {
            case true:
                this->_remote_filters = response;
                configuration_finished = true;
                break;
            case false:
                this->_remote_interface = response;
                interface_selected = true;
                break;
            }
        }

        if (!configuration_finished)
        {
            response = RemoteSniffer::get_nonempty_line();
            Communicator::send(this->_server_sockfd, response);
        }
    }
    this->_sniffer_configured = true;
}

void RemoteSniffer::packet_receiver(std::queue<byte_array>& packet_queue)
{
    if (this->_connect_succeeded == false)
    {
        throw std::runtime_error("RemoteSniffer::connect() wasn't called.");
    }
    if (this->_sniffer_configured == false)
    {
        throw std::runtime_error("RemoteSniffer::configure_sniffer() wasn't called.");
    }

    std::cout << '\n' << "Starting remote sniffer at " << this->_ip << ':' << this->_port << '\n';
    std::cout << "Interface: " << this->_remote_interface << '\n';
    std::cout << "Filters: " << this->_remote_filters << '\n';
    while (true)
    {
        std::string msg = Communicator::recv(this->_server_sockfd);
        std::cout << msg << '\n';
    }
}

std::string RemoteSniffer::get_nonempty_line()
{
    std::string input;
    do
    {
        std::getline(std::cin, input);
    } while (input.size() == 0);
    return input;
}
