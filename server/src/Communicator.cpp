#include "Communicator.h"

void Communicator::send(int32_t client_sockfd, std::string msg)
{
    const char* data = msg.c_str();

    if (::send(client_sockfd, data, msg.size(), 0) == -1)
    {
        throw std::runtime_error("Failed to send message to client.");
    }
}

std::string Communicator::recv(int32_t client_sockfd)
{
    char buf[MAX_RECV_BUF_SIZE];

    if (::recv(client_sockfd, buf, MAX_RECV_BUF_SIZE, 0) == -1)
    {
        throw std::runtime_error("Failed to receive message from client.");
    }
    buf[MAX_RECV_BUF_SIZE - 1] = '\0';

    return std::string(buf);
}
