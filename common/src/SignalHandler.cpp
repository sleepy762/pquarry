#include "SignalHandler.h"

void SignalHandler::set_signal_handler(int sig, void(*handler_func)(int), int flags)
{
    struct sigaction new_action;

    new_action.sa_handler = handler_func;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = flags;
    
    sigaction(sig, &new_action, nullptr);
}
