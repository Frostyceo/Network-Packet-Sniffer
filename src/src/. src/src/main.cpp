#include "sniffer.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <network_interface>" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    Sniffer sniffer(interface);
    sniffer.startCapture();

    return 0;
}
