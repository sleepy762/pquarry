#pragma once
#include <string>
#include <sstream>

#define PACKET_SIZE_LENGTH (5)

class Deserializer
{
public:
    // This edits the data buffer (removes used packet data + packet size bytes)
    static std::string deserialize_data(std::string& data, bool& partial_data_flag);
};
