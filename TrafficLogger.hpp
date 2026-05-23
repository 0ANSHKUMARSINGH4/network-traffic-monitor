#pragma once

#include "PacketParser.hpp"
#include <fstream>
#include <mutex>
#include <string>

class TrafficLogger {
public:
    /**
     * @brief Construct a new Traffic Logger.
     * 
     * @param log_filename Path to the output text log file.
     */
    explicit TrafficLogger(const std::string& log_filename = "traffic_log.txt");

    /**
     * @brief Destroy the Traffic Logger, ensuring all logs are flushed.
     */
    ~TrafficLogger();

    /**
     * @brief Logs the parsed packet info to both console (stylized) and log file.
     * 
     * @param info Parsed packet metadata.
     */
    void logPacket(const PacketInfo& info);

private:
    // Internal logging methods
    void logToConsole(const PacketInfo& info);
    void logToFile(const PacketInfo& info);

    // Helpers
    std::string formatTimestamp(const struct timeval& tv) const;

    std::ofstream file_stream_;
    std::mutex log_mutex_;
    std::string log_filename_;
};
