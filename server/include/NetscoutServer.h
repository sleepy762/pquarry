#pragma once
#include <tins/tins.h>
#include <string>

class NetscoutServer
{
private:
    std::string _ip_address;
    uint16_t _port;

    int32_t _sockfd;

    int64_t _bytes_sent;

public:
    NetscoutServer(std::string ip, uint16_t port);
    ~NetscoutServer();
    
};