#include "LocalSniffer.h"
#include "callback.h"
#include <iostream>
#include "SignalHandler.h"
#include "CapabilitySetter.h"

Sniffer* LocalSniffer::_sniffer = nullptr;

LocalSniffer::LocalSniffer(std::string interface, std::string filters)
{
    this->_interface = interface;
    this->_filters = filters;
}

LocalSniffer::~LocalSniffer()  {}

// Stops the sniffer when Ctrl-C is pressed
void LocalSniffer::sniffer_interrupt(int)
{
    _sniffer->stop_sniff();

    delete _sniffer;
    _sniffer = nullptr;
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
    config.set_immediate_mode(true);

    CapabilitySetter::set_required_caps(CAP_SET);
    // The sniffer is allocated on the heap because we want to access the object in a separate function
    // see LocalSniffer::sniffer_interrupt
    _sniffer = new Sniffer(this->_interface, config);

    // We want the signal handler to work only while sniffing
    SignalHandler::set_signal_handler(SIGINT, LocalSniffer::sniffer_interrupt, 0);

    // Starts the sniffer
    _sniffer->sniff_loop(callback);
    
    // We want to disable the signal handler when we are not sniffing
    SignalHandler::set_signal_handler(SIGINT, SIG_DFL, 0);
    CapabilitySetter::set_required_caps(CAP_CLEAR);
}
