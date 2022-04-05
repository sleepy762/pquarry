#pragma once
#include <tins/tins.h>
#include <string>

using namespace Tins;

class Serializer
{
public:
    static std::string serialize_data(const byte_array& data);
};
