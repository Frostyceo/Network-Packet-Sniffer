cmake_minimum_required(VERSION 3.10)
project(PacketSniffer)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

add_executable(PacketSniffer src/main.cpp src/sniffer.cpp)
target_link_libraries(PacketSniffer ${PCAP_LIBRARIES})
