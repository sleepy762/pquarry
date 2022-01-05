#include "NetscoutServer.h"
#include <iostream>
#include <sstream>
#include <unistd.h>

int main(int argc, char** argv)
{
    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }
    // We expect 3 arguments because the 1st is the executable name, the 2nd is the ip address
    // and the 3rd is the port
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <ip address> <port>" << '\n';
        return 1;
    }
    
    // Converting string to integer to get the port
    std::stringstream strVal;
    strVal << argv[2];
    uint16_t port;
    strVal >> port;

    try
    {
        NetscoutServer server = NetscoutServer(argv[1], port);
        server.start();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
