#include "PacketParser.hpp"
#include <iomanip>
#include <sstream>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <vector>
#include <arpa/inet.h>

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

bool PacketParser::parsePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, PacketInfo& out_info) {
    if (!pkthdr || !packet) {
        return false;
    }

    // Initialize metadata
    out_info.timestamp = pkthdr->ts;
    out_info.packet_len = pkthdr->len;
    out_info.cap_len = pkthdr->caplen;
    out_info.src_port = 0;
    out_info.dest_port = 0;
    out_info.payload_len = 0;
    out_info.flags = "";

    // 1. Layer 2: Ethernet Header
    if (out_info.cap_len < sizeof(struct ether_header)) {
        return false; // Packet too short to even contain Ethernet header
    }

    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);
    out_info.eth_src = formatMAC(eth->ether_shost);
    out_info.eth_dst = formatMAC(eth->ether_dhost);
    out_info.eth_type = ntohs(eth->ether_type);

    // 2. Layer 3: Network Header
    if (out_info.eth_type == ETHERTYPE_IP) {
        // IPv4 Packet
        size_t ip_offset = sizeof(struct ether_header);
        if (out_info.cap_len < ip_offset + sizeof(struct ip)) {
            out_info.protocol_type = "IPv4 (Truncated)";
            return true; // Partially parsed
        }

        const struct ip* ip = reinterpret_cast<const struct ip*>(packet + ip_offset);
        
        // Convert IP addresses to string
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
        
        out_info.ip_src = src_ip_str;
        out_info.ip_dst = dst_ip_str;
        out_info.ip_proto_num = ip->ip_p;

        size_t ip_hdr_len = ip->ip_hl * 4;
        if (ip_hdr_len < sizeof(struct ip) || out_info.cap_len < ip_offset + ip_hdr_len) {
            out_info.protocol_type = "IPv4 (Bad Header)";
            return true;
        }

        // Determine protocol type and parse Layer 4 if available
        if (ip->ip_p == IPPROTO_TCP) {
            out_info.protocol_type = "TCP";
            size_t tcp_offset = ip_offset + ip_hdr_len;
            
            if (out_info.cap_len < tcp_offset + sizeof(struct tcphdr)) {
                out_info.protocol_type = "TCP (Truncated)";
                return true;
            }

            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + tcp_offset);
            out_info.src_port = ntohs(tcp->th_sport);
            out_info.dest_port = ntohs(tcp->th_dport);

            // Parse TCP Flags
            std::vector<std::string> active_flags;
            if (tcp->th_flags & TH_SYN) active_flags.push_back("SYN");
            if (tcp->th_flags & TH_ACK) active_flags.push_back("ACK");
            if (tcp->th_flags & TH_FIN) active_flags.push_back("FIN");
            if (tcp->th_flags & TH_RST) active_flags.push_back("RST");
            if (tcp->th_flags & TH_PUSH) active_flags.push_back("PSH");
            if (tcp->th_flags & TH_URG) active_flags.push_back("URG");

            // Combine flags into a readable string
            std::stringstream flag_ss;
            for (size_t i = 0; i < active_flags.size(); ++i) {
                flag_ss << active_flags[i];
                if (i < active_flags.size() - 1) flag_ss << "|";
            }
            out_info.flags = flag_ss.str();

            // Calculate payload length
            size_t tcp_hdr_len = tcp->th_off * 4;
            uint32_t ip_total_len = ntohs(ip->ip_len);
            
            if (ip_total_len >= (ip_hdr_len + tcp_hdr_len)) {
                out_info.payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
            } else {
                out_info.payload_len = 0;
            }
        } 
        else if (ip->ip_p == IPPROTO_UDP) {
            out_info.protocol_type = "UDP";
            size_t udp_offset = ip_offset + ip_hdr_len;

            if (out_info.cap_len < udp_offset + sizeof(struct udphdr)) {
                out_info.protocol_type = "UDP (Truncated)";
                return true;
            }

            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(packet + udp_offset);
            out_info.src_port = ntohs(udp->uh_sport);
            out_info.dest_port = ntohs(udp->uh_dport);
            
            uint32_t udp_len = ntohs(udp->uh_ulen);
            if (udp_len >= sizeof(struct udphdr)) {
                out_info.payload_len = udp_len - sizeof(struct udphdr);
            } else {
                out_info.payload_len = 0;
            }
        } 
        else if (ip->ip_p == IPPROTO_ICMP) {
            out_info.protocol_type = "ICMP";
            // ICMP length is the rest of the IP payload
            uint32_t ip_total_len = ntohs(ip->ip_len);
            if (ip_total_len >= ip_hdr_len) {
                out_info.payload_len = ip_total_len - ip_hdr_len;
            }
        } 
        else {
            out_info.protocol_type = "IP-Proto-" + std::to_string(ip->ip_p);
            uint32_t ip_total_len = ntohs(ip->ip_len);
            if (ip_total_len >= ip_hdr_len) {
                out_info.payload_len = ip_total_len - ip_hdr_len;
            }
        }
    } 
    else if (out_info.eth_type == ETHERTYPE_IPV6) {
        out_info.protocol_type = "IPv6";
        // Detailed IPv6 header parsing could be added, but for this version, we recognize it as IPv6.
        // We'll set source/destination to MAC or general labels.
        out_info.ip_src = "IPv6-Host";
        out_info.ip_dst = "IPv6-Host";
    } 
    else if (out_info.eth_type == ETHERTYPE_ARP) {
        out_info.protocol_type = "ARP";
        out_info.ip_src = "ARP-Sender";
        out_info.ip_dst = "ARP-Target";
    } 
    else {
        std::stringstream ss;
        ss << "Eth-Type-0x" << std::hex << std::setw(4) << std::setfill('0') << out_info.eth_type;
        out_info.protocol_type = ss.str();
    }

    return true;
}

std::string PacketParser::formatMAC(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]);
        if (i < 5) ss << ":";
    }
    return ss.str();
}
