#pragma once
#include <tins/tins.h>
#include <string>
#include "Communicator.h"
#include <memory>
#include <functional>

using namespace Tins;

using interface_ip_pair = std::pair<std::string, std::string>;

class PQuarryServer
{
private:
    std::unique_ptr<Communicator> _communicator;
    
    // Server related members
    uint16_t _port;
    int32_t _server_sockfd;
    int32_t _client_sockfd;

    // Stores the interfaces which are available on the machine which is running the server
    std::vector<interface_ip_pair> _avail_interfaces;

    // The client sets these
    std::string _chosen_interface;
    std::string _chosen_filters;

    void accept();
    void configure_sniffer_with_client();

    void update_interface_list();
    std::string get_formatted_interfaces_msg() const;
    std::string get_interface_from_client() const;
    bool is_interface_valid(const std::string& interface) const;

    std::string get_filters_from_client() const;
    bool are_filters_valid(std::string& filters, std::string& error_out) const;

    void start_sniffer();

    bool callback(const Packet& packet);

    static std::function<void()> _interrupt_function_wrapper;
    void interrupt_function();
    bool _stop_server;

public:
    PQuarryServer(const PQuarryServer&) = delete;
    PQuarryServer(uint16_t port);
    ~PQuarryServer();
    
    void start();
};
