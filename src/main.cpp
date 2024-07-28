#include "elf_handler.hpp"
#include "helper.hpp"
#include <iostream>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        Helper::Log(Helper::LogLevel::Error, "No executable specified");
        printf("Usage: %s <executable>", argv[0]);
        std::exit(EXIT_FAILURE);
    }

    try
    {
        Helper::InitializeLogFile("application.log");
        ElfHandler elfHandler(argv[1]);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        std::exit(EXIT_FAILURE);
    }

    return 0;
}