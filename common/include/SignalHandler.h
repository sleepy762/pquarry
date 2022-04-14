#pragma once

class SignalHandler
{
private:
    int _signal;
    bool _signal_handler_set;

public:
    SignalHandler(int signal);
    SignalHandler(int signal, void(*handler_func)(int), int flags);
    ~SignalHandler();

    // Sets a new signal handler using sigaction()
    void set_signal_handler(void(*handler_func)(int), int flags);
};
