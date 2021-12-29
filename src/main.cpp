#include "Netscout.h"
#include "NetscoutMenu.h"
#include <unistd.h>

int main(int argc, char** argv)
{
    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }

    Netscout netscout = Netscout::instantiate_with_args(argc, argv);
    netscout.menu_loop();

    return 0;
}
