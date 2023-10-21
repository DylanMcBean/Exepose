#include "helper.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

void LoggingHelper::LogError(int errorCode, const char* errorMessage, ...)
{
    va_list args;
    va_start(args, errorMessage);
    vfprintf(stderr, errorMessage, args);
    va_end(args);
    exit(errorCode);
}