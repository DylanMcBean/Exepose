#pragma once

#include <cstdio>

class LoggingHelper
{
public:
    static void LogError(int errorCode, const char* errorMessage, ...);
};