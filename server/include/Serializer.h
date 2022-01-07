#pragma once
#include <tins/tins.h>
#include <string>
#include <sstream>
#include <iomanip>

using namespace Tins;

#define PACKET_SIZE_LENGTH (5)

class Serializer
{
public:
    static std::string serialize_data(const byte_array& data);
};
