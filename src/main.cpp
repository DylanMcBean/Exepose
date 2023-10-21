#include <iostream>
#include "elf_handler.hpp"
#include "helper.hpp"

int main(int argc, char** argv) 
{
    if (argc < 2)
    {
        LoggingHelper::LogError(1006, "Not enough arguments provided");
        printf("Usage: %s <executable>", argv[0]);
        std::exit(EXIT_FAILURE);
    }

    try 
    {
        ElfHandler elfHandler(argv[1]);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        std::exit(EXIT_FAILURE);
    }

    return 0;
}