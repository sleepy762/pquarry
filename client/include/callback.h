#pragma once
#include <tins/tins.h>
#include <list>

#define MAX_AMOUNT_OF_PACKETS (1000000)

using namespace Tins;

extern std::list<Packet> saved_packets;
extern uint64_t packet_number;

bool callback(const Packet& packet);
