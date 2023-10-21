#include "helper.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

void Helper::LogError(int errorCode, const char *errorMessage, ...)
{
    va_list args;
    va_start(args, errorMessage);
    vfprintf(stderr, errorMessage, args);
    va_end(args);
    exit(errorCode);
}

std::string Helper::toByteEncoded(const uint8_t *data, size_t length)
{
    static const char *hexChars = "0123456789ABCDEF";
    std::string result;
    for (size_t i = 0; i < length; ++i)
    {
        if (data[i] < 0x20 || data[i] > 0x7E)
            result += "\\x" + std::string{hexChars[(data[i] & 0xF0) >> 4], hexChars[data[i] & 0x0F]};
        else
            result += data[i];
    }
    return result;
}