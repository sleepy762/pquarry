#pragma once
#include <tins/tins.h>
#include <iostream>
#include <list>
#include <string>
#include "PacketPrinter.h"
#include "ColorPicker.h"
#include "NetscoutMenu.h"

using namespace Tins;

extern std::list<PDU*> _savedPDUs;

class Netscout
{
    std::string _interface;
    std::string _filters;

    static bool callback(const PDU& pdu);

public:
    Netscout();
    ~Netscout();

    std::string get_interface() const;
    void set_interface(std::string interface);

    std::string get_filters() const;
    void set_filters(std::string filters);

    void menu_loop();

    void start_sniffer() const;
};
