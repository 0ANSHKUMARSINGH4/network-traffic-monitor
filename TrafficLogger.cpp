#include "TrafficLogger.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

// ANSI Escape Codes for stylized console output
#define ANSI_RESET          "\033[0m"
#define ANSI_BOLD           "\033[1m"
#define ANSI_DIM            "\033[2m"
#define ANSI_COLOR_TCP      "\033[1;32m" // Bold Green
#define ANSI_COLOR_UDP      "\033[1;36m" // Bold Cyan
#define ANSI_COLOR_ICMP     "\033[1;35m" // Bold Magenta
#define ANSI_COLOR_ARP      "\033[1;33m" // Bold Yellow
#define ANSI_COLOR_OTHER    "\033[1;31m" // Bold Red
#define ANSI_COLOR_TIME     "\033[90m"   // Dark Gray
#define ANSI_COLOR_ARROW    "\033[33m"   // Yellow Arrow

TrafficLogger::TrafficLogger(const std::string& log_filename)
    : log_filename_(log_filename) {
    
    // Open in append mode
    file_stream_.open(log_filename_, std::ios::out | std::ios::app);
    if (!file_stream_.is_open()) {
        std::cerr << "[WARNING] Could not open traffic log file: " << log_filename_ 
                  << ". Logs will only be printed to the console." << std::endl;
    } else {
        // Write session header to log file
        std::time_t now = std::time(nullptr);
        file_stream_ << "\n=========================================================\n"
                     << "  NEW CAPTURE SESSION STARTED AT " << std::asctime(std::localtime(&now))
                     << "=========================================================\n";
        file_stream_.flush();
    }

    // Print friendly banner to console
    std::cout << ANSI_BOLD << ANSI_COLOR_TCP 
              << "=========================================================\n"
              << "          NETWORK TRAFFIC MONITOR ACTIVATED             \n"
              << "=========================================================\n"
              << ANSI_RESET;
    std::cout << ANSI_DIM << "Logging to file: " << log_filename_ << ANSI_RESET << "\n\n";

    // Column Headers
    std::cout << std::left
              << std::setw(20) << "TIMESTAMP"
              << std::setw(10) << "PROTOCOL"
              << std::setw(45) << "SOURCE -> DESTINATION"
              << std::setw(15) << "LENGTH"
              << std::setw(15) << "PAYLOAD"
              << "INFO / FLAGS\n";
    std::cout << std::string(115, '-') << "\n";
}

TrafficLogger::~TrafficLogger() {
    if (file_stream_.is_open()) {
        std::time_t now = std::time(nullptr);
        file_stream_ << "=========================================================\n"
                     << "  CAPTURE SESSION STOPPED AT " << std::asctime(std::localtime(&now))
                     << "=========================================================\n";
        file_stream_.close();
    }
    std::cout << "\n" << ANSI_BOLD << "Traffic Monitor logging stopped. Goodbye!\n" << ANSI_RESET;
}

void TrafficLogger::logPacket(const PacketInfo& info) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    logToConsole(info);
    logToFile(info);
}

void TrafficLogger::logToConsole(const PacketInfo& info) {
    // Determine Protocol Color
    std::string proto_color = ANSI_COLOR_OTHER;
    if (info.protocol_type == "TCP") {
        proto_color = ANSI_COLOR_TCP;
    } else if (info.protocol_type == "UDP") {
        proto_color = ANSI_COLOR_UDP;
    } else if (info.protocol_type == "ICMP") {
        proto_color = ANSI_COLOR_ICMP;
    } else if (info.protocol_type == "ARP") {
        proto_color = ANSI_COLOR_ARP;
    }

    // Format Timestamp
    std::cout << ANSI_COLOR_TIME << std::left << std::setw(20) << formatTimestamp(info.timestamp) << ANSI_RESET;

    // Format Protocol
    std::cout << proto_color << std::left << std::setw(10) << info.protocol_type << ANSI_RESET;

    // Format Host & Port details
    std::stringstream host_ss;
    if (!info.ip_src.empty()) {
        host_ss << info.ip_src;
        if (info.src_port > 0) host_ss << ":" << info.src_port;
        host_ss << ANSI_COLOR_ARROW << " -> " << ANSI_RESET;
        host_ss << info.ip_dst;
        if (info.dest_port > 0) host_ss << ":" << info.dest_port;
    } else {
        // Fallback to Ethernet (MAC)
        host_ss << info.eth_src << ANSI_COLOR_ARROW << " -> " << ANSI_RESET << info.eth_dst;
    }
    std::cout << std::left << std::setw(45 + (13)) << host_ss.str(); // offset for ANSI color codes inside ss

    // Format lengths
    std::stringstream len_ss;
    len_ss << info.packet_len << " B";
    std::cout << std::left << std::setw(15) << len_ss.str();

    std::stringstream pay_ss;
    pay_ss << info.payload_len << " B";
    std::cout << std::left << std::setw(15) << pay_ss.str();

    // Additional info / flags / MACs
    std::stringstream info_ss;
    if (!info.flags.empty()) {
        info_ss << "[" << info.flags << "] ";
    }
    if (!info.ip_src.empty()) {
        info_ss << ANSI_DIM << "MAC: " << info.eth_src << "->" << info.eth_dst << ANSI_RESET;
    }
    std::cout << info_ss.str() << "\n";
    std::cout << std::flush;
}

void TrafficLogger::logToFile(const PacketInfo& info) {
    if (!file_stream_.is_open()) return;

    // Log format without ANSI escape codes:
    // [TIMESTAMP] PROTOCOL SRC:PORT -> DST:PORT | LEN: X | PAYLOAD: Y | FLAGS/INFO
    file_stream_ << "[" << formatTimestamp(info.timestamp) << "] "
                 << std::left << std::setw(8) << info.protocol_type << " ";

    if (!info.ip_src.empty()) {
        file_stream_ << info.ip_src;
        if (info.src_port > 0) file_stream_ << ":" << info.src_port;
        file_stream_ << " -> " << info.ip_dst;
        if (info.dest_port > 0) file_stream_ << ":" << info.dest_port;
    } else {
        file_stream_ << info.eth_src << " -> " << info.eth_dst;
    }

    file_stream_ << " | LEN: " << info.packet_len << " B"
                 << " | PAYLOAD: " << info.payload_len << " B";

    if (!info.flags.empty()) {
        file_stream_ << " | FLAGS: " << info.flags;
    }
    
    if (!info.ip_src.empty()) {
        file_stream_ << " | MAC: " << info.eth_src << "->" << info.eth_dst;
    }

    file_stream_ << "\n";
    file_stream_.flush();
}

std::string TrafficLogger::formatTimestamp(const struct timeval& tv) const {
    char time_buffer[64];
    std::time_t sec = tv.tv_sec;
    struct std::tm* tm_info = std::localtime(&sec);
    
    std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    std::stringstream ss;
    ss << time_buffer << "." << std::setw(6) << std::setfill('0') << tv.tv_usec;
    return ss.str();
}
