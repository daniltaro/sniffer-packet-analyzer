#include "threatDetector.h"
#include <iostream> 
#include <termcolor/termcolor.hpp>

bool threatDetector::isSuspiciousICMP(std::string& type){
    auto now = std::chrono::steady_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(now - start_timeICMP);
    bool flag = false;
    if(time.count() >= 5){
        if(icmp_count > 20){
            start_timeICMP = now;
            threatCount++;
            flag = true;

            type += "[ICMP FLOOD] ";
            std::cout << termcolor::red << "[ICMP FLOOD] " << 
            termcolor::reset << "detected\n";
        } else {
            start_timeICMP = now;
            icmp_count = 0;
        }
    }
    return flag;
}

bool threatDetector::isSuspiciousTCP(std::string& type){
    auto now = std::chrono::steady_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(now - start_timeTCP);
    bool flag = false;

    if(time.count() >= 5){
        if (tcpSYN > 20 && ((double)tcpACK / tcpSYN) < 0.2){
            start_timeTCP = now;
            tcpACK = 0;
            tcpSYN = 0;
            flag = true;
            threatCount++;

            type += "[SYN FLOOD] ";
            std::cout << termcolor::red << "[SYN FLOOD] " << 
            termcolor::reset << "detected\n";
        } else {
            start_timeTCP = now;
            tcpACK = 0;
            tcpSYN = 0;
        }

        for(const auto& [ip, ports] : TCPscanner){
            if(ports.size() > 100){
                flag = true;
                threatCount++;

                type += "[TCP PORT SCANING] ";
                std::cout << termcolor::red << "[TCP PORT SCANING] " << 
                termcolor::reset << "detected\n";
            }
        }
    }
    return flag;
}

bool threatDetector::issuspiciousUDP(std::string& type){
    auto now = std::chrono::steady_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(now - start_timeUDP);
    bool flag = false;

    if(time.count() >= 5){
        if(UDP_packets > 100){
            start_timeUDP = now;
            UDP_packets = 0;
            flag = true;
            threatCount++;

            type += "[UDP FLOOD] ";
            std::cout << termcolor::red << "[UDP FLOOD] " << 
            termcolor::reset << "detected\n";              
        } else {
            UDP_packets = 0;
            start_timeUDP = now;
        }

        for(const auto& [ip, ports] : UDPscanner){
            if(ports.size() > 100){
                flag = true;
                threatCount++;

                type += "[UDP PORT SCANING] ";
                std::cout << termcolor::red << "[UDP PORT SCANING] " << 
                termcolor::reset << "detected\n";
            }
        }

        
    }
    return flag;
}

void threatDetector::tcpSYNAdd(){
    tcpSYN += 1;
}

void threatDetector::tcpACKAdd(){
    tcpACK += 1;
}

void threatDetector::icmpTypeAdd(){
    icmp_count += 1;
}

void threatDetector::udpAdd(){
    UDP_packets += 1;
}

int threatDetector::getThreatCount() const{
    return threatCount;
}

void threatDetector::addIPv4srcDstTCP(const std::string& ip, const u_int16_t& dst_port){
    TCPscanner[ip].insert(dst_port);
}

void threatDetector::addIPv4srcDstUDP(const std::string& ip, const u_int16_t& dst_port){
    UDPscanner[ip].insert(dst_port);
}