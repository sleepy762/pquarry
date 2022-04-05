#include "Serializer.h"
#include <sstream>
#include <iomanip>

#define PACKET_SIZE_LENGTH (5)

std::string Serializer::serialize_data(const byte_array& data)
{
    std::string serialized_data = "";

    // Appending the packet size
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(PACKET_SIZE_LENGTH) << data.size();
    serialized_data += ss.str();

    // Appending the data
    serialized_data.insert(serialized_data.end(), data.begin(), data.end());

    return serialized_data;
}
