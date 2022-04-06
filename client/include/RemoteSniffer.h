#pragma once
#include <tins/tins.h>
#include "Communicator.h"
#include <string>
#include <memory>

using namespace Tins;

class RemoteSniffer
{
private:
    std::unique_ptr<Communicator> _communicator;
    // Server related members
    std::string _ip;
    uint16_t _port;
    static int32_t _server_sockfd; // Must be static so the signal handler can access it

    // Status members
    bool _connect_succeeded;
    bool _sniffer_configured;

    // Stores the strings that were sent and accepted by the server
    std::string _remote_interface;
    std::string _remote_filters;

    // Like std::getline but the input *must* have more than 0 characters
    // This function is specific for this class
    static std::string get_nonempty_line();

    static void remote_sniffer_interrupt(int);

    void connect();
    void configure_sniffer();
    void packet_receiver();
    void start();

public:
    RemoteSniffer(std::string ip, uint16_t port);
    ~RemoteSniffer();

    void start_sniffer();
};
