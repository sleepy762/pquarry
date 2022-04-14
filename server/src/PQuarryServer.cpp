#include "PQuarryServer.h"
#include <sys/socket.h>
#include <stdexcept>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <sys/ioctl.h>
#include <net/if.h>
#include "Serializer.h"
#include "CapabilitySetter.h"
#include "SignalHandler.h"

#define NO_FILTERS_STR ("no")

#define NS_SERVER_SSL_CERT_FILE ("/.nsServerCert.pem") 
#define NS_SERVER_SSL_KEY_FILE ("/.nsServerKey.pem")

std::function<void()> PQuarryServer::_interrupt_function_wrapper;

PQuarryServer::PQuarryServer(uint16_t port)
{
    this->_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->_server_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Failed to create socket.");
    }

    this->_port = port;
    this->_stop_server = false;
}

PQuarryServer::~PQuarryServer()
{
    if (this->_client_sockfd != INVALID_SOCKET)
    {
        close(this->_client_sockfd);
    }
    close(this->_server_sockfd);
}

// The interfaces are stored in a class member because multiple methods need to access it
void PQuarryServer::update_interface_list()
{
    this->_avail_interfaces.clear();

    char buf[1024];
    struct ifconf ifc;
    struct ifreq* ifr;
    int32_t num_interfaces;

    // Querying the available interfaces
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(this->_server_sockfd, SIOCGIFCONF, &ifc) < 0)
    {
        throw std::runtime_error("Call to ioctl failed.");
    }

    // Iterating the interfaces and adding the IP address too
    ifr = ifc.ifc_req;
    num_interfaces = ifc.ifc_len / sizeof(struct ifreq);
    for (int i = 0; i < num_interfaces; i++)
    {
        struct ifreq* item = &ifr[i];
        
        std::string interface = item->ifr_name;
        std::string ip = inet_ntoa(((struct sockaddr_in*)&item->ifr_addr)->sin_addr);

        this->_avail_interfaces.push_back(interface_ip_pair(interface, ip));
    }
}

void PQuarryServer::start()
{
    struct sockaddr_in sock_addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    sock_addr.sin_port = htons(this->_port);

    if (bind(this->_server_sockfd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0)
    {
        throw std::runtime_error("Binding failed. (Try using a different port)");
    }
    if (listen(this->_server_sockfd, 0) < 0)
    {
        throw std::runtime_error("Error while setting up listener.");
    }

    // If the client disconnects from the SSL socket, the server will terminate because of a broken pipe
    SignalHandler sigpipeHandler(SIGPIPE, SIG_IGN, 0);
    
    _interrupt_function_wrapper = [this]() { this->interrupt_function(); };
    SignalHandler sigintHandler(SIGINT, [](int){_interrupt_function_wrapper();}, 0);

    std::cout << "Press Ctrl+C to stop the server." << '\n';
    std::cout << "Listening on port " << this->_port << '\n';
    // Accept connections until server is closed
    while (true)
    {
        try
        {
            this->accept();
        }
        catch(const std::exception& e)
        {
            if (this->_stop_server)
            {
                break;
            }
            std::cerr << e.what() << '\n';
        }
    }
}

void PQuarryServer::accept()
{
    struct sockaddr_in client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

    this->_client_sockfd = ::accept(this->_server_sockfd, (struct sockaddr*)&client_addr, &client_addrlen);
    if (this->_client_sockfd == INVALID_SOCKET)
    {
        throw std::runtime_error("Accepted invalid socket.");
    }

    // Get the connected client's ip address and port
    char client_ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_address, sizeof(client_ip_address));
    uint16_t client_port = ntohs(client_addr.sin_port);

    std::string home_path = getenv("HOME");
    std::string cert_path = home_path + NS_SERVER_SSL_CERT_FILE;
    std::string pkey_path = home_path + NS_SERVER_SSL_KEY_FILE;

    CapabilitySetter commCaps(CAP_SET);
    this->_communicator = std::unique_ptr<Communicator>(
        new Communicator(this->_client_sockfd, TLS_server_method(), cert_path.c_str(), pkey_path.c_str())
    );
    commCaps.set_required_caps(CAP_CLEAR);

    std::cout << "Client connected at " << client_ip_address << ":" << client_port << '\n';

    this->update_interface_list();
    this->configure_sniffer_with_client();
    this->start_sniffer();
}

void PQuarryServer::configure_sniffer_with_client()
{
    // Get the necessary info from the client 
    this->_chosen_interface = this->get_interface_from_client();
    this->_chosen_filters = this->get_filters_from_client();

    // We should ignore our own traffic
    // This filter removes traffic on the port which we are working with
    if (this->_chosen_filters != "")
    {
        this->_chosen_filters += " and ";
    }
    this->_chosen_filters += "not port " + std::to_string(this->_port);

    this->_communicator->send("Configuration complete!");
}

std::string PQuarryServer::get_interface_from_client() const
{
    bool valid;
    std::string interface;
    std::string fmt_msg = this->get_formatted_interfaces_msg();

    // Send the initial message
    this->_communicator->send(fmt_msg);
    do
    {
        interface = this->_communicator->recv();
        valid = this->is_interface_valid(interface);

        if (!valid)
        {
            this->_communicator->send("Invalid interface.");
        }
    } while (!valid);
    
    return interface;
}

std::string PQuarryServer::get_formatted_interfaces_msg() const
{
    std::string msg;

    msg += "Please choose an interface to capture packets from:\n";
    for (auto it = _avail_interfaces.cbegin(); it != _avail_interfaces.cend(); it++)
    {
        msg += it->first;
        msg += " : IP ";
        msg += it->second;
        // Add a newline if its not the last interface
        if (it + 1 != _avail_interfaces.cend())
        {
            msg += '\n';
        }
    }

    return msg;
}

bool PQuarryServer::is_interface_valid(const std::string& interface) const
{
    for (auto it = _avail_interfaces.cbegin(); it != _avail_interfaces.cend(); it++)
    {
        // The interface is available and valid
        if (it->first == interface)
        {
            return true;
        }
    }
    return false;
}

std::string PQuarryServer::get_filters_from_client() const
{
    bool valid;
    std::string filters = "";
    std::string fmt_msg = "Enter pcap filters (write 'no' for no filters):";

    this->_communicator->send(fmt_msg);
    do
    {
        std::string filter_error = "";

        filters = this->_communicator->recv();

        CapabilitySetter filterCaps(CAP_SET);
        valid = this->are_filters_valid(filters, filter_error);
        filterCaps.set_required_caps(CAP_CLEAR);

        if (!valid)
        {
            std::string msg = "Invalid filters: " + filter_error;
            this->_communicator->send(msg);
        }
    } while (!valid);
    
    return filters;
}

bool PQuarryServer::are_filters_valid(std::string& filters, std::string& error_out) const
{
    // It's impossible to send an empty string and recv it, so we must use some special string
    // It's also important to clear the special string from the filters because it's not valid
    if (filters == NO_FILTERS_STR)
    {
        filters = "";
        return true;
    }

    // Check if the filters are valid
    try
    {
        SnifferConfiguration config;
        config.set_filter(filters);
        Sniffer tempSniffer = Sniffer(this->_chosen_interface, config);
    }
    catch(const std::exception& e)
    {
        error_out = e.what();
        return false;
    }
    return true;
}

void PQuarryServer::start_sniffer()
{
    SnifferConfiguration config;
    config.set_filter(this->_chosen_filters);
    config.set_immediate_mode(true);

    CapabilitySetter snifferCaps(CAP_SET);

    Sniffer sniffer = Sniffer(this->_chosen_interface, config);
    sniffer.set_extract_raw_pdus(true); // Don't interpret packets
    sniffer.sniff_loop([this](const Packet& packet) -> bool
    {
        return this->callback(packet);
    });
}

bool PQuarryServer::callback(const Packet& packet)
{
    std::unique_ptr<PDU> pdu(packet.pdu()->clone());
    byte_array bytes = pdu->serialize();

    std::string bytes_string = Serializer::serialize_data(bytes);
    try
    {
        this->_communicator->send(bytes_string);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return false; // Stop the sniffer
    }

    return true;
}

void PQuarryServer::interrupt_function()
{
    this->_stop_server = true;
}
