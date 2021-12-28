#pragma once
#include <iostream>
#include <string>
#include <limits>
#include "ColorPicker.h"

#define VERSION ("1.0")

#define START_SNIFFER_OPT (1)
#define SET_INTERFACE_OPT (2)
#define SET_FILTERS_OPT (3)
#define EXIT_OPT (4)

class NetscoutMenu
{
public:
    static void main_menu();
    static int get_int();

    static void print_success_msg(const char* msg);
    static void print_error_msg(const char* msg);
};
