#pragma once
#include <iostream>
#include <string>
#include <map>
#include <limits>
#include "ColorPicker.h"

#define VERSION ("1.1.2")

// Enum of menu options
typedef enum menu_entry_index
{
    START_SNIFFER_OPT = 1,
    SET_INTERFACE_OPT,
    SET_FILTERS_OPT,
    EXPORT_PACKETS_OPT,
    CLEAR_SAVED_PACKETS_OPT,
    SEE_INFO_OPT,
    EXIT_OPT
} menu_entry_index;

class NetscoutMenu
{
private:
    // Maps menu option index to menu option text
    static const std::map<menu_entry_index, const char*> _main_menu_entries;

public:
    static void main_menu();
    static int get_int();

    static void print_success_msg(const char* msg);
    static void print_error_msg(const char* msg);
};
