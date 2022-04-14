#include "LocalSniffer.h"
#include <iostream>
#include "SignalHandler.h"
#include "CapabilitySetter.h"
#include "PacketPrinter.h"

LocalSniffer::LocalSniffer(PacketContainer& packet_container, std::string interface, std::string filters)
    : _packet_container(packet_container)
{
    this->_interface = interface;
    this->_filters = filters;
}

LocalSniffer::~LocalSniffer()  {}


std::function<void()> LocalSniffer::_interrupt_function_wrapper;

void LocalSniffer::interrupt_function()
{
    this->_sniffer->stop_sniff();
}

void LocalSniffer::start_sniffer()
{
    // Check if no interface was set
    if (this->_interface == "")
    {
        throw std::runtime_error("You must set an interface.");
    }

    std::cout << "Starting sniffer on interface " << this->_interface << '\n';

    // Instantiate the config to add our pcap filters
    SnifferConfiguration config;
    config.set_filter(this->_filters);
    config.set_immediate_mode(true); // Show packets immediately instead of in waves

    // Set the wrapper interrupt function which will be called inside the interrupt handler    
    _interrupt_function_wrapper = [this]() { this->interrupt_function(); };

    // We want the signal handler to work only while sniffing
    SignalHandler sigintHandler(SIGINT, [](int){_interrupt_function_wrapper();}, 0);
    CapabilitySetter snifferCaps(CAP_SET);

    this->_sniffer = std::unique_ptr<Sniffer>(new Sniffer(this->_interface, config));
    // Starts the sniffer
    this->_sniffer->sniff_loop([this](const Packet& packet)
    {
        PacketPrinter::print_packet(packet);
        this->_packet_container.add_packet(packet);
        return true;
    });
}
