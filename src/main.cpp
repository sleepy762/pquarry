#include <tins/tins.h>
#include <iostream>
#include <unistd.h>

using namespace Tins;

bool callback(const PDU& pdu)
{
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>(); 
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> " 
         << ip.dst_addr() << ':' << tcp.dport() << " " << tcp.pdu_type() << std::endl;
    return true;
}

int main()
{
    if (getuid() != 0)
    {
        std::cerr << "This program must be run as root in order to work." << std::endl;
        return 1;
    }
    Sniffer("enp3s0").sniff_loop(callback);
    return 0;
}
