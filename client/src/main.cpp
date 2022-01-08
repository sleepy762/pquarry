#include "LocalSniffer.h"
#include "NetscoutMenu.h"
#include <unistd.h>

int main(int argc, char** argv)
{
    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }

    LocalSniffer local_sniffer = LocalSniffer::instantiate_with_args(argc, argv);
    local_sniffer.menu_loop();

    return 0;
}
