#pragma once
#include <tins/tins.h>
#include <string>

using namespace Tins;

using interface_ip_pair = std::pair<std::string, std::string>;

#define PCAP_FILE_EXTENSION (".pcap")

class LocalSniffer
{
private:
    std::string _interface;
    std::string _filters;

    static Sniffer* _sniffer;
    static void sniffer_interrupt(int);

public:
    LocalSniffer(std::string interface, std::string filters);
    ~LocalSniffer();

    void start_sniffer();
};
