#include "LoopBackHandler.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>
#include <termcolor/termcolor.hpp>
#include "../headers/EthernetHeader.h"
#include "../headers/Ipv4Header.h"
#include "../headers/TCPHeader.h"
#include "../headers/UDPHeader.h"
#include "../headers/ICMPHeader.h"
#include <thread>

#define LINK_OFFSET 4

using json = nlohmann::json;

LoopBackHandler::LoopBackHandler( bool all,  bool tcp, 
                 bool udp,  bool icmp) {
    all_packets = all;
    tcp_prot = tcp;
    udp_prot = udp;
    icmp_prot = icmp;
}

void LoopBackHandler::printPayload(const u_char *payload, const uint32_t &len) const {
    int offset = 0;

    for (int i = 0; i < len; i += 16) {
        std::cout << "0x" << std::hex << offset << ": ";

        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                printf("%02x ", payload[i + j]);
            } else {
                printf("   ");
            }
        }

        std::cout << " | ";
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                const u_char ch = payload[i + j];
                printf("%c", (ch >= 32 && ch <= 126) ? ch : '.');
            }
        }
        std::cout << '\n';

        offset += 16;
    }
}

void LoopBackHandler::Handle(u_char *user, const struct pcap_pkthdr *header, 
                            const u_char *packet) {
    pack_count++;
    auto *data = reinterpret_cast<UserData *>(user);

    if (data->dump) {
        pcap_dump(reinterpret_cast<u_char *>(data->dump), header, packet);
    }

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    std::string type = "";
    bool show_packet = false;

    //checking for suspicious
    if((icmp_prot || all_packets) && ipv4Header->protocolType() == 1){
        protocolCounter[ICMP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        if(icmpHeader->getType() == 8){
            threatDec.icmpTypeAdd();
        }

        if(threatDec.isSuspiciousICMP(type) == true){
            this->saveStatistic(user, header, packet, true, type);
            show_packet = true;
        } else {
            this->saveStatistic(user, header, packet, false, type);
        }

    } if((tcp_prot || all_packets) && ipv4Header->protocolType() == 6){
        protocolCounter[TCP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;

        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstTCP(ipv4Header->getSrcIP(), tcpHeader->getDstPort());

        if (tcpHeader->getFlag() & 0x02) threatDec.tcpSYNAdd();
        else if(tcpHeader->getFlag() & 0x10) threatDec.tcpACKAdd();

        if(threatDec.isSuspiciousTCP(type) == true){
            this->saveStatistic(user, header, packet, true, type);
            show_packet = true;
        } else {
            this->saveStatistic(user, header, packet, false, type);
        }
        
    } if((udp_prot || all_packets) && ipv4Header->protocolType() == 17){
        protocolCounter[UDP] += 1;
        ipv4Counter[ipv4Header->getSrcIP()]++;
        ipv4Counter[ipv4Header->getDstIP()]++;
        threatDec.udpAdd();

        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);

        threatDec.addIPv4srcDstUDP(ipv4Header->getSrcIP(), udpHeader->getDstPort());

        if(threatDec.issuspiciousUDP(type) == true){
            this->saveStatistic(user, header, packet, true, type);
            show_packet = true;          
        } else {
            this->saveStatistic(user, header, packet, false, type);
        }

    }

    if(show_packet == false) return;

    std::cout << "packet len - " << std::dec << header->caplen << "\n\n";
    std::cout << "IPV4 HEADER:"<< '\n';
    ipv4Header->printIPv4Header();

    //parse and output
    if (ipv4Header->protocolType() == 6) {
        std::cout << '\n';
        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "TCP HEADER:"<< '\n';
        tcpHeader->printTCPHeader();
        const uint8_t dataOffset = (tcpHeader->dataOffsetReservedGet() >> 4) * 4;

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + dataOffset);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength) 
                        << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << termcolor::red << "\n[ " << termcolor::reset << threatDec.getThreatCount()
            << termcolor::red << " THREAT FOUND ]" << termcolor::reset << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + dataOffset;
        printPayload(payload, payloadLength);
    } else if (ipv4Header->protocolType() == 17) {
        std::cout << '\n';
        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "UDP HEADER:"<< '\n';
        udpHeader->printUDPHeader();

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + 8);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength) 
                        << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << termcolor::red << "\n[ " << termcolor::reset << threatDec.getThreatCount()
            << termcolor::red << " THREAT FOUND ]" << termcolor::reset << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + 8;
        printPayload(payload, payloadLength);
    } else if (ipv4Header->protocolType() == 1) {
        std::cout << '\n';
        auto *icmpHeader = (ICMPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        std::cout << "ICMP HEADER:"<< '\n';
        icmpHeader->printICMPHeader();

        if(icmpHeader->getType() == 8){
            threatDec.icmpTypeAdd();
        }

        int icmpLen = 8;
        if (icmpHeader->getType() == 5 || icmpHeader->getType() == 11) {
            switch (icmpHeader->getCode()) {
                case 3:
                case 11:
                case 12: icmpLen = 36;
                    break;
                case 5: icmpLen = 12;
                    break;
                case 13:
                case 14: icmpLen = 20;
                    break;
                default: icmpLen = 8;
                    break;
            }
        }

        std::cout << '\n';
        const uint32_t payloadLength = header->caplen - (LINK_OFFSET + ipHeaderLength + icmpLen);
        if (payloadLength > 0) {
            std::cout << "payload length - " << static_cast<int>(payloadLength)
                         << " bytes" << std::endl;
            std::cout << "PAYLOAD:"<< '\n';
        } else {
            std::cout << "no payload" << std::endl;
            std::cout << termcolor::red << "\n[ " << termcolor::reset << threatDec.getThreatCount()
            << termcolor::red << " THREAT FOUND ]" << termcolor::reset << "\n";
            return;
        }

        const u_char *payload = packet + LINK_OFFSET + ipHeaderLength + icmpLen;
        printPayload(payload, payloadLength);
    }
    else{
        std::cout << "\nunknown IPV4 protocol\n";
    }
    std::cout << termcolor::red << "\n[ " << termcolor::reset << threatDec.getThreatCount()
    << termcolor::red << " THREAT FOUND ]" << termcolor::reset << "\n";
}

void LoopBackHandler::printStatistic() {
    std::cout << "------------------------------" << std::endl;
    std::cout << "TCP protocols - " << std::dec << protocolCounter[TCP] << std::endl;
    std::cout << "UDP protocols - " << std::dec << protocolCounter[UDP] << std::endl;
    std::cout << "ICMP protocols - " << std::dec << protocolCounter[ICMP] << std::endl;
    std::cout << "Threat count - " << std::dec << threatDec.getThreatCount()  << std::endl;
    std::cout << "Packets count - " << pack_count << std::endl;

    for (const auto &entry: ipv4Counter) {
        std::cout << entry.first << " - " << entry.second << std::endl;
    }
    std::cout << "------------------------------" << std::endl;
}

void LoopBackHandler::saveGenStatistic(const std::string &filename) {
    std::fstream out(filename, std::ios::out | std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "File opening error: " << filename << std::endl;
        return;
    }

    out << "{\n";
    out << "  \"TCP\": " << protocolCounter[TCP] << ",\n";
    out << "  \"UDP\": " << protocolCounter[UDP] << ",\n";
    out << "  \"ICMP\": " << protocolCounter[ICMP] << ",\n";
    out << "   \"IP_Stats\": {\n";

    bool first = true;
    for (const auto &entry: ipv4Counter) {
        if (!first) {
            out << ",\n";
        }
        out << "    \"" << entry.first << "\": " << entry.second;
        first = false;
    }
    out << "\n  },\n";
    out << "  \"timestamp\": \"";
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    out << time_str << "\"\n";
    out << "}\n";

    out.close();
}

void LoopBackHandler::saveStatistic(u_char *user, const struct pcap_pkthdr *header,
                                  const u_char *packet, bool flag, const std::string& type) const{
                                    
    auto *data = reinterpret_cast<UserData *>(user);

    json j;
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&time_point);
    time_str.pop_back();
    j["timestamp"] = time_str;

    auto *ipv4Header = (Ipv4Header *) (packet + LINK_OFFSET);
    j["src_ip"] = ipv4Header->getSrcIP();
    j["dst_ip"] = ipv4Header->getDstIP();

    const u_char ihl = ipv4Header->versionIHLGet() & 0x0F;
    const uint16_t ipHeaderLength = ihl * 4;

    if (ipv4Header->protocolType() == 6){
        j["protocol"] = "TCP";
        auto *tcpHeader = (TCPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        j["src_port"] = tcpHeader->getSrcPort();
        j["dst_port"] = tcpHeader->getDstPort();
    }
    else if (ipv4Header->protocolType() == 17){
        j["protocol"] = "UDP";
        auto *udpHeader = (UDPHeader *) (packet + LINK_OFFSET + ipHeaderLength);
        j["src_port"] = udpHeader->getSrcPort();
        j["dst_port"] = udpHeader->getDstPort();
    }
    else if (ipv4Header->protocolType() == 1) j["protocol"] = "ICMP";

    j["length"] = header->caplen;
    j["threat"] = flag;
    if(flag) j["type"] = type;

    if (!data || !data->out || !data->out->is_open()) {
        std::cerr << "Invalid file stream in UserData!" << std::endl;
        return;
    }
    if(commaFlag) *(data->out) << ",\n";
    commaFlag = true;

    static std::mutex lock;
    std::lock_guard<std::mutex> lock_g(lock);
    *(data->out) << j.dump();
}

