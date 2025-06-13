cmake_minimum_required(VERSION 3.30)
project(Sniffer)

set(CMAKE_CXX_STANDARD 20)

add_executable(Sniffer src/main.cpp
        src/headers/EthernetHeader.cpp
        src/headers/EthernetHeader.h
        src/headers/Ipv4Header.cpp
        src/headers/Ipv4Header.h
        src/headers/TCPHeader.cpp
        src/headers/TCPHeader.h
        src/headers/UDPHeader.cpp
        src/headers/UDPHeader.h
        src/headers/ICMPHeader.cpp
        src/headers/ICMPHeader.h
        src/packetHandler/LoopBackHandler.cpp
        src/packetHandler/LoopBackHandler.h
        src/packetHandler/EthernetHandler.h
        src/packetHandler/EthernetHandler.cpp
        src/packetHandler/BaseHandler.h
        src/packetHandler/BaseHandler.cpp
        src/threatDetector/threatDetecor.cpp
        src/threatDetector/threatDetector.h        
        )

find_library(PCAP_LIB pcap  REQUIRED)
find_package(nlohmann_json REQUIRED)

target_include_directories(Sniffer PRIVATE ${CMAKE_SOURCE_DIR}/external/termcolor)
target_link_libraries(Sniffer ${PCAP_LIB} nlohmann_json::nlohmann_json)
