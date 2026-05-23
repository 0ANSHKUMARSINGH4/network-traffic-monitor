#include "CaptureEngine.hpp"
#include "TrafficLogger.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <cstdlib>
#include <algorithm>
#include <cctype>

// Global pointer to CaptureEngine to enable signal handler access
CaptureEngine* g_engine = nullptr;

// Signal handler for SIGINT (Ctrl+C)
void signalHandler(int signal_num) {
    if (signal_num == SIGINT) {
        std::cout << "\n\n[INFO] Interrupt signal (SIGINT) received. Shutting down capture..." << std::endl;
        if (g_engine) {
            g_engine->stopCapture();
        }
    }
}

// Print detailed usage guidelines
void printUsage(const std::string& program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  -i, --interface <device>  Specify the network interface to capture live packets on.\n"
              << "  -f, --filter <expression> BPF packet filter expression (e.g., 'tcp', 'udp', 'port 80').\n"
              << "  -l, --log <filename>      Structured text log output path (Default: traffic_log.txt).\n"
              << "  -h, --help                Show this help message.\n\n"
              << "Examples:\n"
              << "  sudo " << program_name << " -i eth0\n"
              << "  sudo " << program_name << " -i wlan0 -f \"tcp port 443\"\n"
              << "  sudo " << program_name << " --log logs/my_traffic.txt\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string interface_name = "";
    std::string filter_expression = "";
    std::string log_filename = "traffic_log.txt";

    // Parse Command Line Arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                interface_name = argv[++i];
            } else {
                std::cerr << "[ERROR] --interface requires an argument." << std::endl;
                return 1;
            }
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) {
                filter_expression = argv[++i];
            } else {
                std::cerr << "[ERROR] --filter requires an argument." << std::endl;
                return 1;
            }
        } else if (arg == "-l" || arg == "--log") {
            if (i + 1 < argc) {
                log_filename = argv[++i];
            } else {
                std::cerr << "[ERROR] --log requires an argument." << std::endl;
                return 1;
            }
        } else {
            std::cerr << "[ERROR] Unknown option: " << arg << "\n" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    // Interactive Device Selection if interface is not specified
    if (interface_name.empty()) {
        std::cout << "Scanning available network interfaces..." << std::endl;
        auto devices = CaptureEngine::getAvailableInterfaces();
        if (devices.empty()) {
            std::cerr << "[ERROR] No active network interfaces found.\n"
                      << "NOTE: You might need to run the application with root privileges (sudo) to list interfaces." 
                      << std::endl;
            return 1;
        }

        std::cout << "\nAvailable Network Interfaces:\n";
        std::cout << "---------------------------------------------------------\n";
        for (size_t i = 0; i < devices.size(); ++i) {
            std::cout << "  [" << (i + 1) << "] " << devices[i].first << "\n"
                      << "      Description: " << devices[i].second << "\n";
        }
        std::cout << "---------------------------------------------------------\n";

        std::cout << "Enter interface number or name [Default: 1]: ";
        std::string choice;
        std::getline(std::cin, choice);

        // Trim whitespace
        choice.erase(choice.begin(), std::find_if(choice.begin(), choice.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        choice.erase(std::find_if(choice.rbegin(), choice.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), choice.end());

        if (choice.empty()) {
            interface_name = devices[0].first;
        } else {
            // Check if choice is a valid number index
            bool is_number = !choice.empty() && std::all_of(choice.begin(), choice.end(), ::isdigit);
            if (is_number) {
                int idx = std::stoi(choice) - 1;
                if (idx >= 0 && idx < static_cast<int>(devices.size())) {
                    interface_name = devices[idx].first;
                } else {
                    std::cerr << "[ERROR] Invalid selection index: " << choice << ". Exiting." << std::endl;
                    return 1;
                }
            } else {
                // Check if user input is an exact interface name matches
                auto it = std::find_if(devices.begin(), devices.end(), [&](const std::pair<std::string, std::string>& pair) {
                    return pair.first == choice;
                });
                if (it != devices.end()) {
                    interface_name = choice;
                } else {
                    std::cerr << "[ERROR] Interface \"" << choice << "\" not found in scanned list. Exiting." << std::endl;
                    return 1;
                }
            }
        }
    }

    try {
        // Instantiate the Logger (creates file log session and terminal grid header)
        TrafficLogger logger(log_filename);

        // Instantiate the CaptureEngine
        CaptureEngine engine(logger);
        g_engine = &engine;

        // Register signal handler for SIGINT (Ctrl+C)
        std::signal(SIGINT, signalHandler);

        // Start capture loop
        bool success = engine.startCapture(interface_name, filter_expression);
        
        g_engine = nullptr;
        return success ? 0 : 1;

    } catch (const std::exception& e) {
        std::cerr << "\n[CRITICAL ERROR] An unhandled exception occurred: " << e.what() << std::endl;
        return 1;
    }
}
