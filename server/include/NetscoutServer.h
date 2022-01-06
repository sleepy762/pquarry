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
#define NO_FILTERS_STR ("no")

class NetscoutServer
{
private:
    // Server related members
    std::string _ip_address;
    uint16_t _port;
    int32_t _server_sockfd;
    static int32_t _client_sockfd; // Must be static so the callback can access it too

    // Miscellaneous members
    int64_t _bytes_sent;
    std::vector<interface_ip_pair> _avail_interfaces;

    // The client sets these
    std::string _chosen_interface;
    std::string _chosen_filters;

    void accept();
    void configure_sniffer_with_client();

    void acquire_interfaces();
    std::string get_formatted_interfaces_msg() const;
    std::string get_interface_from_client() const;
    bool is_interface_valid(const std::string& interface) const;

    std::string get_filters_from_client() const;
    bool are_filters_valid(std::string& filters, std::string& error_out) const;

    void start_sniffer();

    static bool callback(const Packet& packet);

public:
    NetscoutServer(std::string ip, uint16_t port);
    ~NetscoutServer();
    
    void start();
};
