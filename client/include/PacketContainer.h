#pragma once
#include <tins/tins.h>
#include <list>

#define MAX_AMOUNT_OF_PACKETS (1000000)

using namespace Tins;

class PacketContainer
{
private:
    std::list<Packet> _saved_packets;

public:
    void clear_packets();
    // Adds a packet while making sure not to go over the packet limit
    void add_packet(const Packet& packet);

    // Returns the size of the list of packets
    size_t size() const;

    const std::list<Packet>& get_packet_list() const;
};
