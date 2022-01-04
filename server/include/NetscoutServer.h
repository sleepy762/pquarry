#pragma once
#include <tins/tins.h>
#include <string>
#include <sys/socket.h>
#include <exception>
#include <unistd.h>
#include <iostream>
#include <vector>

using namespace Tins;

class NetscoutServer
{
private:
    std::string _ip_address;
    uint16_t _port;
    int32_t _server_sockfd;
    int32_t _client_sockfd;

    int64_t _bytes_sent;

    void accept();

    std::vector<std::string> get_interfaces() const;
    std::string get_interface_from_client() const;
    bool is_interface_valid(std::string interface) const;

    std::string get_filters_from_client() const;
    bool are_filters_valid(std::string filters) const;

    void start_sniffer(const std::string& interface, const std::string& filters);

    static bool callback(const Packet& packet);

public:
    NetscoutServer(std::string ip, uint16_t port);
    ~NetscoutServer();
    
    void start();
};
