#pragma once
#include <unistd.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <stdexcept>

#define REQUIRED_CAPS_AMOUNT (2)

class CapabilitySetter
{
private:
    static const cap_value_t _cap_list[REQUIRED_CAPS_AMOUNT];

public:
    static void initialize_caps();

    static void set_required_caps();
    static void clear_required_caps();
};
