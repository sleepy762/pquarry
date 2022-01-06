#pragma once
#include <string>
#include <sys/socket.h>
#include <stdexcept>

#define MAX_RECV_BUF_SIZE (1024)

class Communicator
{
public:
    static void send(int32_t server_sockfd, std::string msg);
    static std::string recv(int32_t server_sockfd);
};
