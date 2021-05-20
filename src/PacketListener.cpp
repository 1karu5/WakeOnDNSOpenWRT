#include "PacketListener.h"
#include <iostream>
#include <sstream>
#include <pcap.h>
#include <bitset>

#define READ_TIMEOUT 10
#define SNAPLEN 65536

PacketListener::PacketListener(const Awakener *aw, const std::string &device, const std::string &filter) : aw_(aw) {
    std::cout << "listening on \"" << device << "\"" << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;

    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr << "Can't get netmask for device " << device << std::endl;
        net = 0;
        mask = 0;
    }
    handle_ = pcap_open_live(device.c_str(), SNAPLEN, 1, READ_TIMEOUT, errbuf);
    if (handle_ == nullptr) {
        std::cerr << "Couldn't open device " << device << ": " << errbuf << std::endl;
        throw std::invalid_argument("error");
    }
    int link_type = pcap_datalink(handle_);
    if (link_type == DLT_EN10MB) {
        std::cout << "reading Ethernet interface" << std::endl;
        isRawInterface_ = false;
    } else if (link_type == DLT_RAW) {
        std::cout << "reading raw interface" << std::endl;
        isRawInterface_ = true;
    } else {
        std::cerr << "This program works only on Ethernet networks, not for " << link_type << std::endl;
        throw std::invalid_argument("error");
    }
    if (pcap_compile(handle_, &fp, filter.c_str(), 0, net) == -1) {
        std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle_) << std::endl;
        throw std::invalid_argument("error");
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle_) << std::endl;
        throw std::invalid_argument("error");
    }
}

PacketListener::~PacketListener() {
    if (handle_ != nullptr) {
        std::cout << "closing pcap handle" << std::endl;
        pcap_close(handle_);
    }
}

void PacketListener::run() {
    if (pcap_loop(handle_, -1, got_packet, (std::uint8_t *) this) != 0) {
        std::cerr << "error from  pcap_loop: " << pcap_geterr(handle_) << std::endl;
    }
}

const Awakener *PacketListener::getAwakener() {
    return aw_;
}

bool PacketListener::isRawInterface() const {
    return isRawInterface_;
}


void got_packet(std::uint8_t *current_packetlistener_this, const struct pcap_pkthdr *header,
                const std::uint8_t *pkt_data) {
    PacketListener *packetListener = reinterpret_cast<PacketListener *>(current_packetlistener_this);

    std::uint8_t *packet_end = (std::uint8_t *) (pkt_data + header->len);

    ip_header *ih;
    udp_header *uh;
    dns_header *dh;
    std::uint32_t ip_len;
    std::uint16_t sport, dport;

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + (packetListener->isRawInterface() ? 0 : ETHERNET_HEADER_LENGTH)); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((std::uint8_t *) ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);

    dh = (dns_header *) ((std::uint8_t *) uh + sizeof(udp_header));

    if (dh->z != 0) {
        std::cerr << "Error: dns header field Z is not zero: " << std::bitset<3>(dh->z) << std::endl;
        return;
    }

    std::ostringstream fromIpStream;
    fromIpStream << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4;

    if (VERBOSE) {
        printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, ",
               ih->saddr.byte1,
               ih->saddr.byte2,
               ih->saddr.byte3,
               ih->saddr.byte4,
               sport,
               ih->daddr.byte1,
               ih->daddr.byte2,
               ih->daddr.byte3,
               ih->daddr.byte4,
               dport);
        printf("QR: %d qdcount: %d ancount: %d nscount: %d arcount: %d\n", dh->qr, dh->qdcount, dh->ancount,
               dh->nscount,
               dh->arcount);
    }

    std::uint8_t *question_data = (std::uint8_t *) ((std::uint8_t *) dh + sizeof(dns_header));

    for (int i = 0; i < dh->qdcount; i++) {
        std::string domain_name;
        while (question_data < packet_end && (*question_data & 0b11000000) == 0) {
            //TODO: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            int label_length = *question_data;
            if (label_length == 0) {
                break;
            }
            if (VERBOSE) {
                std::cout << "label " << i << " found, data should be " << label_length << " long: ";
            }

            if (question_data + 1 + label_length < packet_end) {
                std::string label(question_data + 1, question_data + 1 + label_length);
                if (VERBOSE) {
                    std::cout << label << std::endl;
                }
                if (domain_name.length() == 0) {
                    domain_name += label;
                } else {
                    domain_name += "." + label;
                }

                question_data += 1 + label_length;
            } else {
                std::cerr << "packet corrupted?" << std::endl;
                return;
            }
        }
        if (question_data + 4 < packet_end) {
            std::uint16_t qtype = *((std::uint16_t *) question_data);
            question_data += 2;
            std::uint16_t qclass = *((std::uint16_t *) question_data);
            if (VERBOSE) {
                std::cout << "domain: " << domain_name << " QTYPE: " << (int) qtype << std::endl;
            }
            packetListener->getAwakener()->wake(fromIpStream.str(), domain_name);
        } else {
            std::cerr << "packet corrupted, qtype and qclass is missing" << std::endl;
            return;
        }
    }
    if (VERBOSE) {
        std::cout << "read until: " << (void *) question_data << " packet length: " << (void *) packet_end << "  diff: "
                  << (void *) (packet_end - question_data) << std::endl;
    }
}
