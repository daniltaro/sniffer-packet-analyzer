#ifndef ETHERNETHANDLER_H
#define ETHERNETHANDLER_H

#include <pcap.h>
#include <map>
#include "../threatDetector/threatDetector.h"
#include "BaseHandler.h"

class EthernetHandler : public BaseHandler {
    threatDetector threatDec;

    bool all_packets;
    bool tcp_prot;
    bool udp_prot;
    bool icmp_prot;

    mutable bool commaFlag = false;

    std::map<protocolType, int> protocolCounter;
    std::map<std::string, int> ipv4Counter;

    void printPayload(const u_char *payload, const uint32_t &len) const;

public:
    EthernetHandler(bool all, bool tcp, bool udp, bool icmp);

    void Handle(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

    void printStatistic();

    void saveGenStatistic(const std::string &filename);

    void saveStatistic(u_char *user, const struct pcap_pkthdr *header, const u_char *packet,
                 bool flag, const std::string& type) const;

};

#endif //ETHERNETHANDLER_H
