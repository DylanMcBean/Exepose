#include "helper.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

/**
 * Logs an error message to the standard error stream and exits the program with the given error code.
 * @param errorCode The error code to exit the program with.
 * @param errorMessage The error message to log. Can contain format specifiers.
 * @param ... Additional arguments to be substituted in the error message.
 */
void Helper::LogError(int errorCode, const char *errorMessage, ...)
{
    va_list args;
    va_start(args, errorMessage);
    vfprintf(stderr, errorMessage, args);
    va_end(args);
    exit(errorCode);
}

/**
 * Logs an informational message to the standard output stream.
 *
 * @param infoMessage The message to log.
 * @param ...         Optional arguments to format the message with.
 */
void Helper::LogInfo(const char *infoMessage, ...)
{
    va_list args;
    va_start(args, infoMessage);
    vfprintf(stdout, infoMessage, args);
    va_end(args);
}

/**
 * Logs a warning message to the console.
 * @param warningMessage The warning message to log.
 * @param ... Additional arguments to format the warning message.
 */
void Helper::LogWarning(const char *warningMessage, ...)
{
    va_list args;
    va_start(args, warningMessage);
    vfprintf(stdout, warningMessage, args);
    va_end(args);
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