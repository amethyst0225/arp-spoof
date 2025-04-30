#include "utils.h"

// Define EthArpPacket structure
#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void getHostInfo(const char* interfaceName, Ip* ip, Mac* mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ);

    // Get IP address
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        *ip = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
    } else {
        perror("ioctl (SIOCGIFADDR)");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Get MAC address
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        *mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    } else {
        perror("ioctl (SIOCGIFHWADDR)");
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(sock);
}

Mac getMac(pcap_t* pcap, Ip attackerIp, Mac attackerMac, Ip targetIp) {
    EthArpPacket request;
    request.eth_.dmac_ = Mac::broadcastMac(); // 동적으로 브로드캐스트 MAC 설정
    request.eth_.smac_ = attackerMac;
    request.eth_.type_ = htons(EthHdr::Arp);

    request.arp_.hrd_ = htons(ArpHdr::ETHER);
    request.arp_.pro_ = htons(EthHdr::Ip4);
    request.arp_.hln_ = Mac::SIZE;
    request.arp_.pln_ = Ip::SIZE;
    request.arp_.op_ = htons(ArpHdr::Request);
    request.arp_.smac_ = attackerMac;
    request.arp_.sip_ = htonl(uint32_t(attackerIp)); // Cast Ip to uint32_t
    request.arp_.tmac_ = Mac::nullMac(); // 동적으로 NULL MAC 설정
    request.arp_.tip_ = htonl(uint32_t(targetIp)); // Cast Ip to uint32_t

    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&request), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }
 
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
            exit(EXIT_FAILURE);
        }

        auto* eth = (EthHdr*)packet;
     
        if (eth->type_ == htons(EthHdr::Arp)) {
            auto* arp = (ArpHdr*)(packet + sizeof(EthHdr));
            if (arp->op() == ArpHdr::Reply && arp->sip() == targetIp) {
                return Mac(arp->smac_);
            }
        }
    }
}
