#pragma once
#include "Communicator.h"
#include <string>
#include <memory>
#include <functional>
#include "PacketContainer.h"

class RemoteSniffer
{
private:
    PacketContainer& _packet_container;
    std::unique_ptr<Communicator> _communicator;

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
    // This function is specific to this class
    static std::string get_nonempty_line();

    static std::function<void()> _interrupt_function_wrapper;
    void interrupt_function();

    void connect();
    void configure_sniffer();
    void packet_receiver();
    void start();

public:
    RemoteSniffer(PacketContainer& packet_container, std::string ip, uint16_t port);
    RemoteSniffer(const RemoteSniffer&) = delete;
    ~RemoteSniffer();

    void start_sniffer();
};
