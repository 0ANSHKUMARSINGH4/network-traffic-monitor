#include "CaptureEngine.hpp"
#include "PacketParser.hpp"
#include <iostream>
#include <cstring>
#include <stdexcept>

CaptureEngine::CaptureEngine(TrafficLogger& logger)
    : logger_(logger), pcap_handle_(nullptr), is_capturing_(false) {}

CaptureEngine::~CaptureEngine() {
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
    }
}

std::vector<std::pair<std::string, std::string>> CaptureEngine::getAvailableInterfaces() {
    std::vector<std::pair<std::string, std::string>> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[ERROR] Error finding interfaces: " << errbuf << std::endl;
        return devices;
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::string name = d->name;
        std::string desc = d->description ? d->description : "No description available";
        devices.push_back({name, desc});
    }

    if (alldevs) {
        pcap_freealldevs(alldevs);
    }
    return devices;
}

bool CaptureEngine::startCapture(const std::string& interface_name, const std::string& filter_expression) {
    char errbuf[PCAP_ERRBUF_SIZE];
    active_interface_ = interface_name;

    // 1. Open the session in promiscuous mode (1), snaplen 65535, timeout 1000ms
    pcap_handle_ = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (!pcap_handle_) {
        std::cerr << "[ERROR] Could not open device " << interface_name << ": " << errbuf << std::endl;
        return false;
    }

    // 2. Validate Link Layer
    int link_type = pcap_datalink(pcap_handle_);
    if (link_type != DLT_EN10MB) {
        std::cout << "[WARNING] Link type is " << pcap_datalink_val_to_name(link_type) 
                  << " (not Ethernet). Packet parsing might be inaccurate." << std::endl;
    }

    // 3. Apply BPF filter if specified
    if (!filter_expression.empty()) {
        struct bpf_program fp;
        // Compile the filter
        if (pcap_compile(pcap_handle_, &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[ERROR] Couldn't parse filter \"" << filter_expression 
                      << "\": " << pcap_geterr(pcap_handle_) << std::endl;
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
        // Apply the compiled filter
        if (pcap_setfilter(pcap_handle_, &fp) == -1) {
            std::cerr << "[ERROR] Couldn't install filter \"" << filter_expression 
                      << "\": " << pcap_geterr(pcap_handle_) << std::endl;
            pcap_freecode(&fp);
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
        pcap_freecode(&fp);
        std::cout << "Successfully installed BPF filter: \"" << filter_expression << "\"" << std::endl;
    }

    is_capturing_ = true;
    std::cout << "Starting capture on interface: " << interface_name << "...\n" << std::endl;

    // 4. Run the pcap loop. Passes 'this' pointer as the user context argument.
    int result = pcap_loop(pcap_handle_, 0, packetCallback, reinterpret_cast<u_char*>(this));

    is_capturing_ = false;

    // 5. Check loop outcome and display capture statistics
    if (result == -1) {
        std::cerr << "[ERROR] An error occurred during pcap loop: " << pcap_geterr(pcap_handle_) << std::endl;
    } else if (result == -2) {
        std::cout << "\n[INFO] Capture loop terminated gracefully by user." << std::endl;
    }

    struct pcap_stat stats;
    if (pcap_stats(pcap_handle_, &stats) >= 0) {
        std::cout << "\n--------------------- Session Stats ---------------------" << std::endl;
        std::cout << " Packets received by filter: " << stats.ps_recv << std::endl;
        std::cout << " Packets dropped by kernel: " << stats.ps_drop << std::endl;
        std::cout << " Packets dropped by driver: " << stats.ps_ifdrop << std::endl;
        std::cout << "---------------------------------------------------------" << std::endl;
    }

    pcap_close(pcap_handle_);
    pcap_handle_ = nullptr;

    return result != -1;
}

void CaptureEngine::stopCapture() {
    if (pcap_handle_ && is_capturing_) {
        // Safe to call from any thread or signal handler
        pcap_breakloop(pcap_handle_);
    }
}

void CaptureEngine::packetCallback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    CaptureEngine* engine = reinterpret_cast<CaptureEngine*>(user_data);
    if (engine) {
        engine->handlePacket(pkthdr, packet);
    }
}

void CaptureEngine::handlePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo info;
    if (PacketParser::parsePacket(pkthdr, packet, info)) {
        logger_.logPacket(info);
    }
}
