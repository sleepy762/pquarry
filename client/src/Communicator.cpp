#include "Communicator.h"

void Communicator::send(int32_t server_sockfd, std::string msg)
{
    if (msg.size() == 0)
    {
        throw std::runtime_error("Can't send empty message.");
    }
    
    const char* data = msg.c_str();
    if (::send(server_sockfd, data, msg.size(), MSG_NOSIGNAL) == -1)
    {
        throw std::runtime_error("Failed to send message to server. (Server closed)");
    }
}

std::string Communicator::recv(int32_t server_sockfd)
{
    char buf[MAX_RECV_BUF_SIZE] = {0};

    ssize_t bytes_received = ::recv(server_sockfd, buf, MAX_RECV_BUF_SIZE, 0);
    if (bytes_received <= 0)
    {
        throw std::runtime_error("Failed to receive message from server. (Server closed)");
    }
    buf[bytes_received] = '\0';

    return std::string(buf, bytes_received);
}