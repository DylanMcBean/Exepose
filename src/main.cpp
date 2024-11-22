#include "elf_handler.hpp"
#include "logger.hpp"
#include <iostream>

int main(int argc, char **argv)
{
    LOG_INIT("log.txt");
    if (argc < 2)
    {
        LOG(Logger::LogLevel::Error, "No executable specified");
        printf("Usage: %s <executable>", argv[0]);
        std::exit(EXIT_FAILURE);
    }

    try
    {
        ElfHandler elfHandler(argv[1]);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        std::exit(EXIT_FAILURE);
    }

    return 0;
}