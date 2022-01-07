#include "Deserializer.h"

std::string Deserializer::deserialize_data(std::string& data, bool& partial_data_flag)
{
    std::stringstream ss;
    // The first bytes are the packet size
    ss << data.substr(0, PACKET_SIZE_LENGTH);
    unsigned int packet_size;
    ss >> packet_size;

    std::string deserialized_data = "";

    // Checking the data size without the 5 bytes of the packet size
    if (data.size() - PACKET_SIZE_LENGTH < packet_size)
    {
        partial_data_flag = true;
    }
    else
    {
        // Remove the 'packet size' bytes
        data.erase(0, PACKET_SIZE_LENGTH);
        
        deserialized_data = data.substr(0, packet_size);
        data.erase(0, packet_size); // Remove the packet data
    }

    return deserialized_data;
}
