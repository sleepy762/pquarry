#pragma once
#include <sys/capability.h>

#define REQUIRED_CAPS_AMOUNT (1)

class CapabilitySetter
{
private:
    static const cap_value_t _cap_list[REQUIRED_CAPS_AMOUNT];

public:
    static void initialize_caps();

    static void set_required_caps(cap_flag_value_t flag);
};
