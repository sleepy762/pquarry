#pragma once
#include <tins/tins.h>
#include <string>
#include <sys/socket.h>
#include <stdexcept>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <sys/ioctl.h>
#include <net/if.h>
#include "Communicator.h"

using namespace Tins;

using interface_ip_pair = std::pair<std::string, std::string>;
using interface_ip_pair_vector = std::vector<interface_ip_pair>;

class NetscoutServer
{
private:
    std::string _ip_address;
    uint16_t _port;
    int32_t _server_sockfd;
    int32_t _client_sockfd;

    int64_t _bytes_sent;
    interface_ip_pair_vector _avail_interfaces;

    void accept();

    void acquire_interfaces();
    std::string get_formatted_interfaces_msg() const;
    std::string get_interface_from_client() const;
    bool is_interface_valid(std::string& interface) const;

    std::string get_filters_from_client() const;
    bool are_filters_valid(std::string& filters) const;

    void start_sniffer(const std::string& interface, const std::string& filters);

    static bool callback(const Packet& packet);

public:
    NetscoutServer(std::string ip, uint16_t port);
    ~NetscoutServer();
    
    void start();
};
