#pragma once
#include <tins/tins.h>
#include <string>

#define ANSI_RGB(r, g, b) ("\033[38;2;"#r";"#g";"#b"m")
#define RESET_COLOR ("\033[0m")

#define DEFAULT_COLOR (ANSI_RGB(255,255,255))

#define ERROR_COLOR (ANSI_RGB(217,35,35))
#define SUCCESS_COLOR (ANSI_RGB(35,217,83))

using namespace Tins;

class ColorPicker
{
public:
    static const char* get_color_by_pdu_type(const PDU::PDUType type);
};
