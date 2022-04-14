#include "SignalHandler.h"
#include <signal.h>

SignalHandler::SignalHandler(int signal)
{
    this->_signal = signal;
    this->_signal_handler_set = false;
}

SignalHandler::SignalHandler(int signal, void(*handler_func)(int), int flags)
{
    this->_signal = signal;
    this->set_signal_handler(handler_func, flags);
}

SignalHandler::~SignalHandler()
{
    if (this->_signal_handler_set)
    {
        this->set_signal_handler(SIG_DFL, 0);
    }
}

void SignalHandler::set_signal_handler(void(*handler_func)(int), int flags)
{
    struct sigaction new_action;

    new_action.sa_handler = handler_func;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = flags;
    
    sigaction(this->_signal, &new_action, nullptr);
    this->_signal_handler_set = true;
}
