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

    PacketContainer packet_container;
    NetscoutMenu menu = NetscoutMenu(packet_container, argc, argv);
    menu.menu_loop();

    return 0;
}
