

#ifndef WAKEONDNS_PACKETLISTENER_H
#define WAKEONDNS_PACKETLISTENER_H

#include "Awakener.h"
#include <string>
#include <pcap.h>

#define ETHERNET_HEADER_LENGTH 14
#define VERBOSE false

class PacketListener {
public:
    PacketListener(const Awakener *aw, const std::string &device, const std::string &filter);
    ~PacketListener();
    void run();
    const Awakener* getAwakener();
    bool isRawInterface() const;
private:
    pcap_t *handle_;
    const Awakener *aw_;
    bool isRawInterface_ = false;
};

void got_packet(std::uint8_t *args, const struct pcap_pkthdr *header,
                const std::uint8_t *pkt_data);

/* 4 bytes IP address */
typedef struct ip_address {
    std::uint8_t byte1;
    std::uint8_t byte2;
    std::uint8_t byte3;
    std::uint8_t byte4;
} ip_address;

/* IPv4 header */
typedef struct ip_header {
    std::uint8_t ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    std::uint8_t tos;            // Type of service
    std::uint16_t tlen;           // Total length
    std::uint16_t identification; // Identification
    std::uint16_t flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    std::uint8_t ttl;            // Time to live
    std::uint8_t proto;          // Protocol
    std::uint16_t crc;            // Header checksum
    ip_address saddr;      // Source address
    ip_address daddr;      // Destination address
    std::uint32_t op_pad;         // Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header {
    std::uint16_t sport;          // Source port
    std::uint16_t dport;          // Destination port
    std::uint16_t len;            // Datagram length
    std::uint16_t crc;            // Checksum
} udp_header;


typedef struct dns_header {      // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    std::uint16_t id;
    bool qr: 1;
    unsigned int opcode: 4;
    bool aa: 1;
    bool tc: 1;
    bool rd: 1;
    bool ra: 1;
    unsigned int z: 3;
    unsigned int rcode: 4;
    std::uint16_t qdcount;
    std::uint16_t ancount;
    std::uint16_t nscount;
    std::uint16_t arcount;
} dns_header;


#endif //WAKEONDNS_PACKETLISTENER_H
