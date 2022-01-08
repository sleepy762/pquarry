#pragma once
#include <tins/tins.h>
#include <iostream>
#include <list>
#include <string>
#include <memory>
#include "PacketPrinter.h"
#include "ColorPicker.h"
#include "NetscoutMenu.h"
#include "RemoteSniffer.h"
#include "SignalHandler.h"

using namespace Tins;

#define PCAP_FILE_EXTENSION (".pcap")

class LocalSniffer
{
private:
    std::string _local_interface;
    std::string _local_filters;

    // These static members are members which are used by the static functions below
    static Sniffer* _sniffer;
    static std::list<Packet> _saved_packets;
    static uint32_t _packet_number;

    static bool callback(const Packet& packet);
    static void sniffer_interrupt(int);

    // We must friend RemoteSniffer in order to let it use our callback
    friend class RemoteSniffer;

public:
    LocalSniffer();
    LocalSniffer(std::string interface, std::string filters);
    ~LocalSniffer();

    static LocalSniffer instantiate_with_args(int argc, char** argv);

    std::string get_interface() const;
    // Setter
    void set_interface(std::string interface);
    // Gets the interface from the user and then sets it with the above setter
    void set_interface();

    std::string get_filters() const;
    // Setter
    void set_filters(std::string filters);
    // Gets the filters from the user and then sets them with the above setter
    void set_filters();

    void menu_loop();

    void export_packets() const;

    void clear_saved_packets();

    void see_information() const;

    void start_sniffer();

    void connect_to_remote_sniffer();
};
