#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>
#include <source_location>
#include <unordered_map>
#include <fstream>
#include <memory>
#include <cstdarg>

struct SourceLocationHash {
    std::size_t operator()(const std::source_location& loc) const noexcept {
        std::size_t hash = std::hash<std::string_view>{}(loc.file_name());
        hash ^= std::hash<unsigned int>{}(loc.line()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<unsigned int>{}(loc.column()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<std::string_view>{}(loc.function_name()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
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

class Logger {
public:
    enum class LogLevel {
        Debug,
        Info,
        Warning,
        Error
    };

    static Logger& Instance();
    
    void InitializeLogFile(const std::string& logFilePath);
    
    std::runtime_error Log(LogLevel level, const char* format, const std::source_location location = std::source_location::current(), ...);

    static std::string toByteEncoded(const uint8_t* data, size_t length);

private:
    Logger() = default; // singleton instance
    void outputLog(LogLevel level, const std::string& message, const std::source_location& location);

    std::ofstream logFile;
    bool logFileInitialized = false;
    std::unordered_map<std::source_location, uint64_t, SourceLocationHash, SourceLocationEqual> logDict;
};

#define LOG(level, format, ...) Logger::Instance().Log(level, format, std::source_location::current(), ##__VA_ARGS__)
#define LOG_THROW(level, format, ...) throw Logger::Instance().Log(level, format, std::source_location::current(), ##__VA_ARGS__)
#define LOG_INIT(logFilePath) Logger::Instance().InitializeLogFile(logFilePath)