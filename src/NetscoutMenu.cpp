#include "NetscoutMenu.h"

const std::map<int, const char*> NetscoutMenu::_main_menu_entries = 
{
    { START_SNIFFER_OPT, "Start sniffer" },
    { SET_INTERFACE_OPT, "Set interface" },
    { SET_FILTERS_OPT, "Set pcap filters" },
    { EXPORT_PACKETS_OPT, "Export packets into pcap" },
    { CLEAR_SAVED_PACKETS_OPT, "Clear saved packets"},
    { SEE_INFO_OPT, "See information" },
    { EXIT_OPT, "Exit" }
};

void NetscoutMenu::print_success_msg(const char* msg)
{
    std::cout << SUCCESS_COLOR << msg << RESET_COLOR << '\n';
}

void NetscoutMenu::print_error_msg(const char* msg)
{
    std::cerr << ERROR_COLOR << msg << RESET_COLOR << '\n';
}

// Will not return until an integer is given
int NetscoutMenu::get_int()
{
    int input;
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

void NetscoutMenu::main_menu()
{
    std::cout << '\n' << "NetScout Version " << VERSION << '\n';
    for (auto it = _main_menu_entries.cbegin(); it != _main_menu_entries.cend(); it++)
    {
        std::cout << '[' << it->first << ']' << ' ' << it->second << '\n';
    }
    std::cout << "Select an option: ";
}
