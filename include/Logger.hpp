/**
 * @file Logger.hpp
 * @brief Thread-safe colorized console and system logger for kvault.
 */

#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <string_view>
#include <mutex>
#include <chrono>
#include <iomanip>

namespace kvault {

/**
 * @class Logger
 * @brief Thread-safe logging facility supporting multiple severity tiers.
 */
class Logger {
public:
    enum class Level {
        Debug,
        Info,
        Warn,
        Error,
        Kernel
    };

    static void setMinLevel(Level level) noexcept {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_minLevel = level;
    }

    static void log(Level level, std::string_view msg) {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (level < s_minLevel) return;

        // ANSI Color sequences
        const char* colorCode = "\033[0m";
        const char* tag = "INFO";

        switch (level) {
        case Level::Debug:
            colorCode = "\033[90m"; // Gray
            tag = "DEBUG";
            break;
        case Level::Info:
            colorCode = "\033[32m"; // Green
            tag = "INFO ";
            break;
        case Level::Warn:
            colorCode = "\033[33m"; // Yellow
            tag = "WARN ";
            break;
        case Level::Error:
            colorCode = "\033[1;31m"; // Bold Red
            tag = "ERROR";
            break;
        case Level::Kernel:
            colorCode = "\033[1;35m"; // Bold Magenta
            tag = "KERNEL";
            break;
        }

        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm_buf{};
        localtime_r(&in_time_t, &tm_buf);

        std::cout << colorCode
                  << "[" << std::put_time(&tm_buf, "%H:%M:%S")
                  << "." << std::setfill('0') << std::setw(3) << ms.count()
                  << "] [" << tag << "] "
                  << msg << "\033[0m\n" << std::flush;
    }

    static void debug(std::string_view msg) { log(Level::Debug, msg); }
    static void info(std::string_view msg)  { log(Level::Info, msg); }
    static void warn(std::string_view msg)  { log(Level::Warn, msg); }
    static void error(std::string_view msg) { log(Level::Error, msg); }
    static void kernel(std::string_view msg){ log(Level::Kernel, msg); }

private:
    static inline std::mutex s_mutex;
    static inline Level s_minLevel{Level::Info};
};

} // namespace kvault


#endif // LOGGER_HPP
