#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <stdexcept>
#include <source_location>
#include <unordered_map>
#include <tuple>
#include <fstream>

struct SourceLocationHash {
    std::size_t operator()(const std::source_location& loc) const noexcept {
        std::size_t hash = 0;
        // Hash the file name
        std::hash<std::string_view> hash_fn;
        hash ^= hash_fn(loc.file_name()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        // Hash the line number
        hash ^= std::hash<unsigned int>{}(loc.line()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        // Hash the column number
        hash ^= std::hash<unsigned int>{}(loc.column()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        // Hash the function name
        hash ^= hash_fn(loc.function_name()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        return hash;
    }
};

struct SourceLocationEqual {
    bool operator()(const std::source_location& lhs, const std::source_location& rhs) const noexcept {
        return lhs.file_name() == rhs.file_name() &&
               lhs.line() == rhs.line() &&
               lhs.column() == rhs.column() &&
               lhs.function_name() == rhs.function_name();
    }
};

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

    static std::runtime_error Log(LogLevel level, const char *format, const std::source_location location = std::source_location::current(), ...);
    static std::string toByteEncoded(const uint8_t *data, size_t length);

    // Method to initialize log file
    static void InitializeLogFile(const std::string& logFilePath);

private:
    static std::ofstream logFile;
    static bool logFileInitialized;
    static std::unordered_map<std::source_location, uint64_t, SourceLocationHash, SourceLocationEqual> logDict;
};