#include "NetscoutMenu.h"

// Will not return until an integer is given
int NetscoutMenu::get_int()
{
    int input;
    while(true)
    {
        std::cin >> input;
        std::cin.ignore();
        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cerr << "Invalid input." << '\n';
        }
        else
        {
            break;
        }
    }
    return input;
}

void NetscoutMenu::main_menu()
{
    std::cout << "NetScout Version " << VERSION << '\n';
    std::cout << "[1] Start sniffer" << '\n';
    std::cout << "[2] Set interface" << '\n';
    std::cout << "[3] Set filters (manually)" << '\n';
    std::cout << "[4] Exit" << '\n';
    std::cout << "Select an option please: "; 
}
