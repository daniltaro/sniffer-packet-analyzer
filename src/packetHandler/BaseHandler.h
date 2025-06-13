#ifndef BASEHANDLER_H
#define BASEHANDLER_H

#include <pcap.h>
#include <string>
#include <fstream>
#include <iostream>

enum protocolType {
    ALL = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
};

class BaseHandler {
protected:
    int pack_count = 0;
public:
    virtual void Handle(u_char *user, const struct pcap_pkthdr 
            *header, const u_char *packet) = 0;
    virtual void printStatistic() = 0;
    virtual void saveGenStatistic(const std::string&) = 0;
    virtual ~BaseHandler() {}
    static void StaticHandle(u_char *user, 
        const struct pcap_pkthdr *header, const u_char *packet);
};

struct UserData {
    pcap_dumper_t *dump;
    BaseHandler *handler;
    std::fstream *out;
};

#endif//BASEHANDLER_H