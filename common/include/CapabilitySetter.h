#pragma once
#include <sys/capability.h>

#define REQUIRED_CAPS_AMOUNT (1)

class CapabilitySetter
{
private:
    static const cap_value_t _cap_list[REQUIRED_CAPS_AMOUNT];
    bool _caps_set;

public:
    CapabilitySetter();
    CapabilitySetter(cap_flag_value_t flag);
    ~CapabilitySetter();

    static void initialize_caps();

    void set_required_caps(cap_flag_value_t flag);
};
