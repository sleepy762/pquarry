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

void RemoteSniffer::packet_receiver(std::queue<byte_array>& packet_queue)
{
    if (this->_connect_succeeded == false)
    {
        throw std::runtime_error("RemoteSniffer::connect() must be called first.");
    }

    while (true)
    {
        std::string msg = Communicator::recv(this->_server_sockfd);
        std::cout << msg << '\n';
        std::string response;
        std::getline(std::cin, response);
        Communicator::send(this->_server_sockfd, response);
    }
}
