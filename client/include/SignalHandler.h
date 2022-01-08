#pragma once
#include <signal.h>

class SignalHandler
{
public:
    // Sets a new signal handler using sigaction()
    static void set_signal_handler(int sig, void(*handler_func)(int), int flags);
};
