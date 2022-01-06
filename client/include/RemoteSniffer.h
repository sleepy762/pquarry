#pragma once
#include <tins/tins.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include "Communicator.h"
#include "Netscout.h"

using namespace Tins;

#define INVALID_SUBSTR ("Invalid")

class RemoteSniffer
{
private:
    // Server related members
    std::string _ip;
    uint16_t _port;
    int32_t _server_sockfd;

    // Status members
    bool _connect_succeeded;
    bool _sniffer_configured;

    // Stores the strings that were sent and accepted by the server
    std::string _remote_interface;
    std::string _remote_filters;

    // Like std::getline but the input *must* have more than 0 characters
    // This function is specific for this class
    static std::string get_nonempty_line();

    // TODO, close socket when SIGINT is sent
    static void remote_sniffer_interrupt(int);

    void connect();
    void configure_sniffer();
    void packet_receiver();

public:
    RemoteSniffer(std::string ip, uint16_t port);
    ~RemoteSniffer();

    void start();
};
