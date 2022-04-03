#include <unistd.h>
#include <iostream>
#include "NetscoutMenu.h"
#include "CapabilitySetter.h"

int main()
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
    
    NetscoutMenu menu = NetscoutMenu();
    menu.menu_loop();

    return 0;
}
