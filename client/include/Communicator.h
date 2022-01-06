#pragma once
#include <string>
#include <sys/socket.h>
#include <stdexcept>

#define MAX_PACKET_SIZE (65536)
#define MAX_RECV_BUF_SIZE (MAX_PACKET_SIZE)

class Communicator
{
public:
    static void send(int32_t server_sockfd, std::string msg);
    static std::string recv(int32_t server_sockfd);
};
