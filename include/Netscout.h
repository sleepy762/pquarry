#pragma once
#include <tins/tins.h>
#include <iostream>
#include <list>
#include <string>
#include <signal.h>
#include "PacketPrinter.h"
#include "ColorPicker.h"
#include "NetscoutMenu.h"

using namespace Tins;

class Netscout
{
    std::string _interface;
    std::string _filters;

    static Sniffer* _sniffer;
    static std::list<PDU*> _savedPDUs;
    static unsigned int _packet_number;

    static bool callback(const PDU& pdu);
    static void sniffer_interrupt(int);

public:
    Netscout();
    ~Netscout();

    std::string get_interface() const;
    void set_interface(std::string interface);
    void set_interface();

    std::string get_filters() const;
    void set_filters(std::string filters);
    void set_filters();

    void menu_loop();

    void export_packets() const;

    void clear_saved_packets();

    void see_information() const;

    void start_sniffer();
};
