#include "NetscoutServer.h"
#include <iostream>
#include <sstream>
#include <unistd.h>
#include "Version.h"
#include "CapabilitySetter.h"

int main(int argc, char** argv)
{
    // We expect a port to be passed as an argument
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <port>" << '\n';
        return 1;
    }

    // Reduce root permissions
    if (geteuid() == 0)
    {
        try
        {
            CapabilitySetter::initialize_caps();
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            return 1;
        }
        setuid(getuid());
    }
    else
    {
        std::cerr << "The server must be run with the setuid file permission." << '\n';
        return 1;
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
