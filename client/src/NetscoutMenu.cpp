#include "NetscoutMenu.h"

const std::map<menu_entry_index, const char*> NetscoutMenu::_main_menu_entries = 
{
    { START_SNIFFER_OPT, "Start sniffer" },
    { CONNECT_TO_REMOTE_SNIFFER_OPT, "Connect to remote sniffer" },
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

void NetscoutMenu::main_menu()
{
    std::cout << '\n' << "NetScout Version " << CLIENT_VERSION << '\n';
    for (auto it = _main_menu_entries.cbegin(); it != _main_menu_entries.cend(); it++)
    {
        std::cout << '[' << it->first << ']' << ' ' << it->second << '\n';
    }
    std::cout << "Select an option: ";
}
