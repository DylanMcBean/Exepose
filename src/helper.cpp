#include "helper.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <exception>

std::runtime_error Helper::Log(uint64_t code, LogLevel level, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // Pre-format the code and log level
    const char* levelStr;
    const char* colorCode;
    FILE* stream = stdout;

    switch (level)
    {
    case LogLevel::Debug:
        levelStr = "Debug";
        colorCode = "\033[36m";
        break;
    case LogLevel::Info:
        levelStr = "Info";
        colorCode = "\033[32m";
        code <<= 16;
        break;
    case LogLevel::Warning:
        levelStr = "Warning";
        colorCode = "\033[33m";
        code <<= 32;
        break;
    case LogLevel::Error:
        levelStr = "Error";
        colorCode = "\033[31m";
        code <<= 48;
        stream = stderr;
        break;
    default:
        levelStr = "Unknown";
        colorCode = "\033[0m";
        code <<= 64;
        break;
    }

    // Log level, code, and icon
    fprintf(stream, "%s[%016lX] %s\033[0m: ", colorCode, code, levelStr);

    // Log the actual message
    vfprintf(stream, format, args);
    fprintf(stream, "\n");

    va_end(args);

    return std::runtime_error(levelStr);
}

/**
 * Converts a byte array to a string of its hexadecimal representation.
 * Non-printable characters are represented as escape sequences.
 * 
 * @param data The byte array to be converted.
 * @param length The length of the byte array.
 * @return A string of the hexadecimal representation of the byte array.
 */
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