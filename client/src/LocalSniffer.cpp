#include "LocalSniffer.h"
#include "callback.h"
#include <iostream>
#include "SignalHandler.h"
#include "CapabilitySetter.h"

Sniffer* LocalSniffer::_sniffer_ptr = nullptr;

LocalSniffer::LocalSniffer(std::string interface, std::string filters)
{
    this->_interface = interface;
    this->_filters = filters;
}

LocalSniffer::~LocalSniffer()  {}

// Stops the sniffer when Ctrl-C is pressed
void LocalSniffer::sniffer_interrupt(int)
{
    _sniffer_ptr->stop_sniff();
    
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

    CapabilitySetter::set_required_caps(CAP_SET);

    std::unique_ptr<Sniffer> sniffer(new Sniffer(this->_interface, config));
    // We need to access the sniffer in the interrupt function, so we store the pointer
    _sniffer_ptr = sniffer.get();

    // We want the signal handler to work only while sniffing
    SignalHandler::set_signal_handler(SIGINT, LocalSniffer::sniffer_interrupt, 0);

    // Starts the sniffer
    sniffer->sniff_loop(callback);

    CapabilitySetter::set_required_caps(CAP_CLEAR);
}
