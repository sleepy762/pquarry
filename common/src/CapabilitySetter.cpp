#include "CapabilitySetter.h"

// List of the required capabilities for the program
const cap_value_t CapabilitySetter::_cap_list[REQUIRED_CAPS_AMOUNT] = 
{ CAP_NET_RAW };

void CapabilitySetter::initialize_caps()
{
    cap_t caps = cap_get_proc();
    if (caps == NULL)
    {
        throw std::runtime_error("Failed to get process capabilities.");
    }

    // Clear all the root permissions
    if (cap_clear(caps) == -1)
    {
        throw std::runtime_error("Failed to clear capabilities.");
    }

    // Set only the required capabilities in the permitted section
    if (cap_set_flag(caps, CAP_PERMITTED, REQUIRED_CAPS_AMOUNT, _cap_list, CAP_SET) == -1)
    {
        throw std::runtime_error("Call to cap_set_flag failed.");
    }

    if (cap_set_proc(caps) == -1)
    {
        throw std::runtime_error("Failed to initialize process capabilities.");
    }
    cap_free(caps);
}

void CapabilitySetter::set_required_caps()
{
    cap_t caps = cap_get_proc();
    if (caps == NULL)
    {
        throw std::runtime_error("Failed to get process capabilities.");
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, REQUIRED_CAPS_AMOUNT, _cap_list, CAP_SET) == -1)
    {
        throw std::runtime_error("Call to cap_set_flag failed.");
    }

    if (cap_set_proc(caps) == -1)
    {
        throw std::runtime_error("Failed to update process capabilities.");
    }
    cap_free(caps);
}

void CapabilitySetter::clear_required_caps()
{
    cap_t caps = cap_get_proc();
    if (caps == NULL)
    {
        throw std::runtime_error("Failed to get process capabilities.");
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, REQUIRED_CAPS_AMOUNT, _cap_list, CAP_CLEAR) == -1)
    {
        throw std::runtime_error("Call to cap_set_flag failed.");
    }

    if (cap_set_proc(caps) == -1)
    {
        throw std::runtime_error("Failed to update process capabilities.");
    }
    cap_free(caps);
}
