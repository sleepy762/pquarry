#pragma once
#include <tins/tins.h>
#include <string>
#include <functional>
#include <memory>

using namespace Tins;

using interface_ip_pair = std::pair<std::string, std::string>;

#define PCAP_FILE_EXTENSION (".pcap")

class LocalSniffer
{
private:
    std::string _interface;
    std::string _filters;

    std::unique_ptr<Sniffer> _sniffer;

    static std::function<void()> _interrupt_function_wrapper;
    void interrupt_function();

public:
    LocalSniffer(std::string interface, std::string filters);
    ~LocalSniffer();

    void start_sniffer();
};
