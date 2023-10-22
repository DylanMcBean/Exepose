#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

class Helper
{
  public:
    static void LogError(int errorCode, const char *errorMessage, ...);
    static void LogInfo(const char *infoMessage, ...);
    static void LogWarning(const char *warningMessage, ...);
    static std::string toByteEncoded(const uint8_t *data, size_t length);
};