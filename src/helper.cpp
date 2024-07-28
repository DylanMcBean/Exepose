#include "helper.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <sstream>
#include <iomanip>

std::ofstream Helper::logFile;
bool Helper::logFileInitialized = false;
std::unordered_map<std::source_location, uint64_t, SourceLocationHash, SourceLocationEqual> Helper::logDict;

void Helper::InitializeLogFile(const std::string& logFilePath)
{
    if (!logFileInitialized)
    {
        logFile.open(logFilePath, std::ios::app);
        if (!logFile.is_open())
        {
            throw std::runtime_error("Failed to open log file: " + logFilePath);
        }
        logFileInitialized = true;
    }
}

/**
 * Logs a message to both the console and a log file if initialized.
 * 
 * This function handles variable arguments, formats them according to the specified log level, and outputs the result
 * to the console or log file. It also tracks the number of log messages from each source location.
 * 
 * @param level The severity level of the log message (e.g., Debug, Info, Warning, Error).
 * @param format A format string that specifies how subsequent arguments are converted for output.
 * @param location Provides information about the source location (file name, function name, line number).
 * @param ... The variable arguments to be formatted and logged.
 * @return A std::runtime_error instance representing the log level.
 */
std::runtime_error Helper::Log(LogLevel level, const char *format, const std::source_location location, ...)
{
    va_list args;
    va_start(args, location);

    static const std::unordered_map<LogLevel, std::tuple<std::string, std::string, FILE*>> logLevelMap = {
        {LogLevel::Debug,   {"Debug",   "\033[36m", stdout}},
        {LogLevel::Info,    {"Info",    "\033[32m", stdout}},
        {LogLevel::Warning, {"Warning", "\033[33m", stdout}},
        {LogLevel::Error,   {"Error",   "\033[31m", stderr}}
    };

    const auto& [levelStr, colorCode, stream] = logLevelMap.at(level);

    if (logDict.find(location) == logDict.end())
    {
        logDict[location] = logDict.size() + 1;
    }
    uint64_t logDictIndex = logDict[location];

    std::ostringstream logStream;
    logStream << colorCode << "[" << std::hex << std::setw(4) << std::setfill('0') << logDictIndex << "] " << levelStr << "\033[0m: ";

    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    logStream << buffer;

    fprintf(stream, "%s\n", logStream.str().c_str());

    if (logFile.is_open())
    {
        std::ostringstream fileStream;
        fileStream << "[" << location.file_name() << ":" << location.function_name() << ":" << location.line() << "] " << levelStr << " " << buffer;
        logFile << fileStream.str() << std::endl;
        logFile.flush();
    }

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
    static const char hexChars[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(length * 4); // Reserve space for performance

    for (size_t i = 0; i < length; ++i)
    {
        if (data[i] < 0x20 || data[i] > 0x7E)
        {
            result += "\\x";
            result += hexChars[(data[i] >> 4) & 0x0F];
            result += hexChars[data[i] & 0x0F];
        }
        else
        {
            result += static_cast<char>(data[i]);
        }
    }
    return result;
}