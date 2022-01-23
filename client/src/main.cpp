#include <unistd.h>
#include "LocalSniffer.h"
#include "NetscoutMenu.h"
#include "CapabilitySetter.h"
#include <sstream>

int main(int argc, char** argv)
{
    // Reduce root permissions
    if (geteuid() == 0)
    {
        // try
        // {
        //     CapabilitySetter::initialize_caps();
        // }
        // catch(const std::exception& e)
        // {
        //     std::cerr << e.what() << '\n';
        //     exit(1);
        // }
        // int a;
        // std::cin >> a;
        // CapabilitySetter::set_required_caps();
        // std::stringstream strVal;
        // uint16_t uid;

        // strVal << getenv("SUDO_UID");
        // strVal >> uid;

        // setuid(uid);
        // CapabilitySetter::clear_required_caps();
        // std::cout << geteuid() << " " << getuid() << '\n';
    }
    
    LocalSniffer local_sniffer = LocalSniffer::instantiate_with_args(argc, argv);
    local_sniffer.menu_loop();

    return 0;
}
