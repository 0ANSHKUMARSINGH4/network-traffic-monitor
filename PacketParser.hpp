#pragma once

#include <string>
#include <cstdint>
#include <sys/time.h>
#include <pcap.h>

/**
 * @brief Structured representation of parsed packet metadata.
 */
struct PacketInfo {
    // Timing and size
    struct timeval timestamp;
    uint32_t packet_len;      // Actual packet length on wire
    uint32_t cap_len;         // Captured packet length

    // Layer 2: Ethernet
    std::string eth_src;
    std::string eth_dst;
    uint16_t eth_type;

    // Layer 3: Network (IPv4 / IPv6 / ARP etc.)
    std::string ip_src;
    std::string ip_dst;
    std::string protocol_type; // e.g. "TCP", "UDP", "ICMP", "IPv6", "ARP", "Other"
    uint8_t ip_proto_num;      // IP Protocol number (e.g. 6 for TCP, 17 for UDP)

    // Layer 4: Transport (TCP / UDP)
    uint16_t src_port;
    uint16_t dest_port;
    std::string flags;         // TCP flags (e.g. "SYN, ACK") or empty
    uint32_t payload_len;      // Payload size in bytes
};

class PacketParser {
public:
    /**
     * @brief Safely parses a raw packet captured by libpcap.
     * 
     * @param pkthdr Pointer to the pcap packet header (contains timestamp and lengths).
     * @param packet Pointer to the raw packet bytes.
     * @param out_info Output structure containing the parsed fields.
     * @return true if parsing succeeded (at least Layer 2/3), false otherwise.
     */
    static bool parsePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, PacketInfo& out_info);

private:
    // Helper to format MAC addresses
    static std::string formatMAC(const uint8_t* mac);
};
