#include "LocalSniffer.h"
#include "callback.h"
#include <iostream>
#include "SignalHandler.h"
#include "CapabilitySetter.h"

LocalSniffer::LocalSniffer(std::string interface, std::string filters)
{
    this->_interface = interface;
    this->_filters = filters;
}

LocalSniffer::~LocalSniffer()  {}


std::function<void()> LocalSniffer::_interrupt_function_wrapper;

void LocalSniffer::interrupt_function()
{
    this->_sniffer->stop_sniff();

    // We want to disable the signal handler when we are not sniffing
    SignalHandler::set_signal_handler(SIGINT, SIG_DFL, 0);
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

    CapabilitySetter::set_required_caps(CAP_SET);

    this->_sniffer = std::unique_ptr<Sniffer>(new Sniffer(this->_interface, config));

    // We want the signal handler to work only while sniffing
    SignalHandler::set_signal_handler(SIGINT, [](int){_interrupt_function_wrapper();}, 0);

    // Starts the sniffer
    this->_sniffer->sniff_loop(callback);

    CapabilitySetter::set_required_caps(CAP_CLEAR);
}
