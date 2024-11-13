#include "sniffer.h"
#include <iostream>
#include <arpa/inet.h>

Sniffer::Sniffer(const std::string& interface) : interface(interface), handle(nullptr) {}

void Sniffer::startCapture() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, error_buffer);

    if (!handle) {
        std::cerr << "Failed to open device " << interface << ": " << error_buffer << std::endl;
        return;
    }

    std::cout << "Capturing packets on " << interface << "..." << std::endl;
    pcap_loop(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        reinterpret_cast<Sniffer*>(args)->processPacket(header, packet);
    }, reinterpret_cast<u_char*>(this));

    pcap_close(handle);
}

void Sniffer::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "Captured a packet with length: " << header->len << " bytes" << std::endl;

    // Example: Print source and destination IP for IP packets
    struct iphdr* ip_header = (struct iphdr*)(packet + 14);
    struct in_addr src, dest;
    src.s_addr = ip_header->saddr;
    dest.s_addr = ip_header->daddr;

    std::cout << "Source IP: " << inet_ntoa(src) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(dest) << std::endl;
}
