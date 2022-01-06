#include "Communicator.h"

void Communicator::send(int32_t client_sockfd, std::string msg)
{
    if (msg.size() == 0)
    {
        throw std::runtime_error("Can't send empty message.");
    }
    
    const char* data = msg.c_str();
    if (::send(client_sockfd, data, msg.size(), 0) == -1)
    {
        throw std::runtime_error("Failed to send message to client. (Client disconnected)");
    }
}

std::string Communicator::recv(int32_t client_sockfd)
{
    char buf[MAX_RECV_BUF_SIZE];

    ssize_t bytes_received = ::recv(client_sockfd, buf, MAX_RECV_BUF_SIZE, 0);
    if (bytes_received <= 0)
    {
        throw std::runtime_error("Failed to receive message from client. (Client disconnected)");
    }
    buf[bytes_received] = '\0';

    return std::string(buf, bytes_received);
}
