#include "NetscoutServer.h"
#include <iostream>
#include <sstream>
#include <unistd.h>
#include "Version.h"
#include "CapabilitySetter.h"

int main(int argc, char** argv)
{
    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }
    // We expect a port to be passed as an argument
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <port>" << '\n';
        return 1;
    }

    // Reduce root permissions
    try
    {
        CapabilitySetter::initialize_caps();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        exit(1);
    }

    // Converting string to integer to get the port
    std::stringstream strVal;
    strVal << argv[1];
    uint16_t port;
    strVal >> port;

    std::cout << "Starting NetScout Server Version " << SERVER_VERSION << '\n';
    try
    {
        NetscoutServer server = NetscoutServer(port);
        server.start();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
