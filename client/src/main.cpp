#include "LocalSniffer.h"
#include "NetscoutMenu.h"

int main(int argc, char** argv)
{
    LocalSniffer local_sniffer = LocalSniffer::instantiate_with_args(argc, argv);
    local_sniffer.menu_loop();

    return 0;
}
