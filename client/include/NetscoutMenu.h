#pragma once
#include <string>
#include <map>
#include <vector>
#include <limits>
#include <iostream>

// Enum of menu options
typedef enum menu_entry_index
{
    START_LOCAL_SNIFFER_OPT = 1,
    START_REMOTE_SNIFFER_OPT,
    SET_INTERFACE_OPT,
    SET_FILTERS_OPT,
    EXPORT_PACKETS_OPT,
    CLEAR_SAVED_PACKETS_OPT,
    SEE_INFO_OPT,
    EXIT_OPT
} menu_entry_index;

using interface_ip_pair = std::pair<std::string, std::string>;

class NetscoutMenu
{
private:
    std::string _local_interface;
    std::string _local_filters;

    std::vector<interface_ip_pair> get_interface_list() const;

    // Maps menu option index to menu option text
    static const std::map<menu_entry_index, const char*> _main_menu_entries;

    // Setter
    void set_interface(std::string interface);
    // Gets the interface from the user and then sets it with the above setter
    void set_interface();

    // Setter
    void set_filters(std::string filters);
    // Gets the filters from the user and then sets them with the above setter
    void set_filters();

    void export_packets() const;

    void clear_saved_packets() const;

    void see_information() const;

    void print_main_menu() const;

    void start_local_sniffer() const;
    void start_remote_sniffer() const;

public:
    NetscoutMenu();
    NetscoutMenu(std::string interface, std::string filters);
    ~NetscoutMenu();

    static NetscoutMenu instantiate_with_args(int argc, char** argv);

    template <typename T>
    static T get_value();

    static void print_success_msg(const char* msg);
    static void print_error_msg(const char* msg);

    void menu_loop();
};

// Will not return until a value is given (of the given type)
template <typename T>
T NetscoutMenu::get_value()
{
    T input;
    bool fail;
    do
    {
        std::cin >> input;
        std::cin.ignore();

        fail = std::cin.fail();
        if (fail)
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            NetscoutMenu::print_error_msg("Invalid input.");
        }
    } while(fail);
    return input;
}
