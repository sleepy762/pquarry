#include "RemoteSniffer.h"
#include <tins/tins.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include "Deserializer.h"
#include "CapabilitySetter.h"
#include "SignalHandler.h"
#include "PacketPrinter.h"

using namespace Tins;

#define INVALID_SUBSTR ("Invalid")

#define NS_CLIENT_SSL_CERT_FILE ("/.nsClientCert.pem")
#define NS_CLIENT_SSL_KEY_FILE ("/.nsClientKey.pem")

std::function<void()> RemoteSniffer::_interrupt_function_wrapper;

RemoteSniffer::RemoteSniffer(PacketContainer& packet_container, std::string ip, uint16_t port)
    : _packet_container(packet_container)
{
    this->_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->_server_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Failed to create socket.");
    }
    this->_ip = ip;
    this->_port = port;

    this->_connect_succeeded = false;
    this->_sniffer_configured = false;
}

RemoteSniffer::~RemoteSniffer()
{
    close(this->_server_sockfd);
}

void RemoteSniffer::start_sniffer()
{
    this->connect();
    this->configure_sniffer();
    this->packet_receiver();
}

void RemoteSniffer::connect()
{
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(this->_port);

    if (inet_pton(AF_INET, this->_ip.c_str(), &serv_addr.sin_addr) <= 0)
    {
        throw std::runtime_error("Invalid address.");
    }
    if (::connect(this->_server_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        throw std::runtime_error("Connection failed.");
    }

    std::string home_path = getenv("HOME");
    std::string cert_path = home_path + NS_CLIENT_SSL_CERT_FILE;
    std::string pkey_path = home_path + NS_CLIENT_SSL_KEY_FILE;

    CapabilitySetter commCaps(CAP_SET);
    // The communicator is instantiated here instead of in the constructor in order to avoid
    // potentially creating SSL files when the connection won't succeed
    // It's just not needed early on
    this->_communicator = std::unique_ptr<Communicator>(
        new Communicator(this->_server_sockfd, TLS_client_method(), cert_path.c_str(), pkey_path.c_str())
    );
    this->_connect_succeeded = true;
}

void RemoteSniffer::configure_sniffer()
{
    if (this->_connect_succeeded == false)
    {
        throw std::runtime_error("RemoteSniffer::connect() wasn't called.");
    }

    bool configuration_finished = false;
    // "interface_selected" acts as a switch for setting both the interface and filters members of this class
    // while it's false, the interface is being set, when it becomes true, the filters will be set
    bool interface_selected = false;
    std::string response = "";
    while (!configuration_finished)
    {
        std::string server_msg = this->_communicator->recv();
        std::cout << server_msg << '\n';

        // Check if the substring "Invalid" is in the server_msg
        if (server_msg.substr(0, server_msg.find(' ')) != INVALID_SUBSTR && response != "")
        {
            switch (interface_selected)
            {
            case true:
                this->_remote_filters = response;
                configuration_finished = true;
                break;
            case false:
                this->_remote_interface = response;
                interface_selected = true;
                break;
            }
        }

        if (!configuration_finished)
        {
            response = RemoteSniffer::get_nonempty_line();
            this->_communicator->send(response);
        }
    }
    this->_sniffer_configured = true;
}

void RemoteSniffer::packet_receiver()
{
    if (this->_connect_succeeded == false)
    {
        throw std::runtime_error("RemoteSniffer::connect() wasn't called.");
    }
    if (this->_sniffer_configured == false)
    {
        throw std::runtime_error("RemoteSniffer::configure_sniffer() wasn't called.");
    }

    _interrupt_function_wrapper = [this]() { this->interrupt_function(); };
    // Set a handler to close the socket and return to the main menu upon interrupt
    SignalHandler sigintHandler(SIGINT, [](int){_interrupt_function_wrapper();}, 0);
    
    std::cout << '\n' << "Starting remote sniffer at " << this->_ip << ':' << this->_port << '\n';
    std::cout << "Interface: " << this->_remote_interface << '\n';
    std::cout << "Filters: " << this->_remote_filters << '\n';

    std::string data_buffer = "";
    while (true)
    {
        data_buffer += this->_communicator->recv();
        bool partial_data_flag = false;

        while (data_buffer.size() > 0)
        {
            std::string single_packet_data = Deserializer::deserialize_data(data_buffer, partial_data_flag);
            if (partial_data_flag) 
            {
                // If we have partial data, don't contruct a packet, instead receive more data
                break;
            }

            EthernetII eth_pdu = EthernetII((const uint8_t*)single_packet_data.c_str(), single_packet_data.size());
            Packet packet = Packet(eth_pdu);

            PacketPrinter::print_packet(packet);
            this->_packet_container.add_packet(packet);
        }
    }
}

void RemoteSniffer::interrupt_function()
{
    // Terminate the connection to return to the main menu
    close(this->_server_sockfd);
}

std::string RemoteSniffer::get_nonempty_line()
{
    std::string input;
    do
    {
        std::getline(std::cin, input);
    } while (input.size() == 0);
    return input;
}
