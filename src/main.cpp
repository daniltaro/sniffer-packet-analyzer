#include <pcap.h>
#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include "packetHandler/EthernetHandler.h"
#include "packetHandler/LoopBackHandler.h"
#include "packetHandler/BaseHandler.h"

void stopHandle(pcap_t *handle);

int main() {
    
    //error buffer
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;

    if (pcap_findalldevs(&devs, ebuf) == -1) {
        std::cerr << "pcap_findalldevs" << std::endl;
        return -1;
    }

    //writes all devs
    std::cout << "devs:" << std::endl;
    pcap_if_t *temp = devs;
    while (temp != nullptr) {
        std::cout << temp->name << '\n';
        temp = temp->next;
    }
    pcap_freealldevs(devs);

    std::cout << "choose wich one to listen: ";
    std::string dev;
    std::getline(std::cin, dev);

    std::cout << "what protocol (TCP, UDP, ICMP, ALL) to investigate: ";
    std::string protocol;
    std::getline(std::cin, protocol);

    bool all = false;
    bool tcp = false;
    bool udp = false;
    bool icmp = false;

    if (protocol != "ALL" && protocol != "all") {
        protocol += ' ';
        std::string protocol;

        for (int i = 0; i < protocol.length(); ++i) {
            if (protocol[i] == ' ') {
                if (protocol == "ICMP" || protocol == "icmp") icmp = true;
                else if (protocol == "UDP" || protocol == "udp") udp = true;
                else if (protocol == "TCP" || protocol == "tcp") tcp = true;
                else {
                    std::cout << "unknown protocol - " << protocol << std::endl;
                    return -1;
                }
                protocol = "";
            } else {
                protocol += protocol[i];
            }
        }
    } else all = true;

    std::cout << "write pcap file name to save (or press ENTER to skip): ";
    std::string pcap_file_name;
    std::getline(std::cin, pcap_file_name);
    pcap_dumper_t *dump = nullptr;

    std::cout << "write general json file name to save (or press ENTER to skip): ";
    std::string json_file_name1;
    std::getline(std::cin, json_file_name1);

    std::cout << "write json file name to save all stats: ";
    std::string json_file_name2;
    std::getline(std::cin, json_file_name2);

    if (json_file_name2.empty()){
        std::cerr << "write json file name to save all stats!!!" << std::endl;
        return -1;
    }

    std::fstream out(json_file_name2, std::ios::out | std::ios::binary);
    if(!out.is_open()) {
    	std::cerr << "could not open file" << json_file_name2 << std::endl;
    	return -1;
    }
    out << "[\n";

    //opens listening for dev
    pcap_t *handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 10, ebuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live error" << std::endl;
        return -1;
    }

    //defines link type
    int link_type = pcap_datalink(handle);
    bool loopback = false;
    bool ethernet = false;
    if (link_type == DLT_EN10MB) {
        ethernet = true;
    } else if (link_type == DLT_NULL || link_type == DLT_LOOP) {
        loopback = true;
    } else {
        std::cerr << "unsupported link type" << std::endl;
        return -1;
    }

    if (!pcap_file_name.empty()) {
        dump = pcap_dump_open(handle, pcap_file_name.c_str());
        if (dump == nullptr) {
            std::cerr << "error opening pcap file: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            return -1;
        }
    }

    BaseHandler* handler = nullptr;
    EthernetHandler ethHandler(all, tcp, udp, icmp);
    LoopBackHandler loopHandler(all, tcp, udp, icmp);

    if (ethernet) {
        handler = &ethHandler;
    } else if (loopback) {
        handler = &loopHandler;
    }
    
    //saving data as user in pcap_loop
    UserData data{};
    data.dump = dump;
    data.handler = handler;
    data.out = &out;

    std::cout << "press 's' to stop listening...\n\n";
    std::thread th1(stopHandle, handle);//stops reading packets if it read s

    //listening
    std::thread th2([&]() {
        pcap_loop(handle, -1, BaseHandler::StaticHandle, reinterpret_cast<u_char *>(&data));
    });

    th1.join();
    th2.join();

    if (dump) {
        pcap_dump_close(dump);
    }
    pcap_close(handle);

    handler->printStatistic();
    if (!json_file_name1.empty()) {
        handler->saveGenStatistic(json_file_name1);
    }

    out << "\n]";
    out.close();

    return 0;
}

void stopHandle(pcap_t *handle) {
    while (true) {
        char flag;
        std::cin >> flag;
        if (flag == 's') {
            pcap_breakloop(handle);
            return;
        }
    }
}


