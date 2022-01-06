#pragma once
#include <iostream>
#include <string>
#include <map>
#include <limits>
#include "ColorPicker.h"
#include "Version.h"

// Enum of menu options
typedef enum menu_entry_index
{
    START_SNIFFER_OPT = 1,
    CONNECT_TO_REMOTE_SNIFFER_OPT,
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
    
    template <typename T>
    static T get_value();

    static void print_success_msg(const char* msg);
    static void print_error_msg(const char* msg);
};

// Will not return until a value is given (of the given type)
template <typename T>
T NetscoutMenu::get_value()
{
    T input;
    while(true)
    {
        std::cin >> input;
        std::cin.ignore();
        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            NetscoutMenu::print_error_msg("Invalid input.");
        }
        else
        {
            break;
        }
    }
    return input;
}
