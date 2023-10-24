#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <stdexcept>

class Helper
{
  public:
    enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error
    };

    static std::runtime_error Log(uint64_t code, LogLevel level, const char *message, ...);
    static std::string toByteEncoded(const uint8_t *data, size_t length);
};