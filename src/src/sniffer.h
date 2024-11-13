#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>

class Sniffer {
public:
    Sniffer(const std::string& interface);
    void startCapture();

private:
    std::string interface;
    pcap_t* handle;

    void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif
