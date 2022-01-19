#include <unistd.h>
#include "LocalSniffer.h"
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
    }
    
    LocalSniffer local_sniffer = LocalSniffer::instantiate_with_args(argc, argv);
    local_sniffer.menu_loop();

    return 0;
}
