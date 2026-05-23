#pragma once

#include "TrafficLogger.hpp"
#include <string>
#include <vector>
#include <pcap.h>

class CaptureEngine {
public:
    /**
     * @brief Construct a new Capture Engine.
     * 
     * @param logger Reference to a TrafficLogger for packet printing/logging.
     */
    explicit CaptureEngine(TrafficLogger& logger);

    /**
     * @brief Destroy the Capture Engine, closing any open pcap sessions.
     */
    ~CaptureEngine();

    /**
     * @brief Lists all available network interfaces on the host.
     * 
     * @return std::vector<std::string> List of network interface names.
     */
    static std::vector<std::pair<std::string, std::string>> getAvailableInterfaces();

    /**
     * @brief Starts capturing live packets on a specified network interface.
     * 
     * @param interface_name Name of the network interface (e.g. "eth0", "wlan0").
     * @param filter_expression BPF packet filter expression (optional, e.g. "tcp port 80").
     * @return true if capture completed successfully or was stopped by user, false on critical errors.
     */
    bool startCapture(const std::string& interface_name, const std::string& filter_expression = "");

    /**
     * @brief Breaks the active packet capture loop, allowing graceful exit.
     */
    void stopCapture();

private:
    // Packet arrival callback required by libpcap
    static void packetCallback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    // Parse and handle the raw packet
    void handlePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);

    TrafficLogger& logger_;
    pcap_t* pcap_handle_;
    std::string active_interface_;
    bool is_capturing_;
};
