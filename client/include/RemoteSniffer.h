#pragma once
#include <tins/tins.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <queue>
#include <iostream>
#include "Communicator.h"

using namespace Tins;

class RemoteSniffer
{
private:
    std::string _ip;
    uint16_t _port;
    int32_t _server_sockfd;

    bool _connect_succeeded;

public:
    RemoteSniffer(std::string ip, uint16_t port);
    ~RemoteSniffer();

    void connect();
    void packet_receiver(std::queue<byte_array>& packet_queue);
};
