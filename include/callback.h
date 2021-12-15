#pragma once
#include <tins/tins.h>
#include <iostream>
#include <list>
#include <chrono>
#include "PacketPrinter.h"

using namespace Tins;

extern std::list<PDU*> savedPDUs;

bool callback(const PDU& pdu);
