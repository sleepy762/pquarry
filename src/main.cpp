#include "callback.h"
#include <unistd.h>

int main(int argc, char* argv[])
{
    if (getuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }
    // Call menu here
    if (argc != 2)
    {
        std::cout << "Usage: " << *argv << " <interface>" << std::endl;
        return 1;
    }
    std::cout << "Starting sniffer on interface " << argv[1] << std::endl;
    Sniffer(argv[1]).sniff_loop(callback);
    return 0;
}
