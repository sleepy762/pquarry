#include "PacketContainer.h"

void PacketContainer::clear_packets()
{
    this->_saved_packets.clear();
}

void PacketContainer::add_packet(const Packet& packet)
{
    // Limit the amount of packets that can be saved in memory
    if (this->_saved_packets.size() >= MAX_AMOUNT_OF_PACKETS)
    {
        this->_saved_packets.erase(this->_saved_packets.begin());
    }
    this->_saved_packets.push_back(packet); // Stores a copy
}

const std::list<Packet>& PacketContainer::get_packet_list() const
{
    return this->_saved_packets;
}

size_t PacketContainer::size() const
{
    return this->_saved_packets.size();
}
