#include <unistd.h>
#include <iostream>
#include "NetscoutMenu.h"
#include "CapabilitySetter.h"

int main(int argc, char** argv)
{
    // Reduce root permissions
    if (geteuid() == 0)
    {
        try
        {
            CapabilitySetter::initialize_caps();
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            exit(1);
        }
        setuid(getuid());
    }
    
    // I want to keep NetscoutMenu on the stack so I'm just doing it this way
    if (argc > 1)
    {
        NetscoutMenu menu = NetscoutMenu::instantiate_with_args(argc, argv);
        menu.menu_loop();
    }
    else
    {
        NetscoutMenu menu = NetscoutMenu();
        menu.menu_loop();
    }

    return 0;
}
