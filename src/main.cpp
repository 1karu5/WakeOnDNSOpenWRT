#include <iostream>
#include <pcap.h>
#include <bitset>
#include <string>

int READ_TIMEOUT = 10;
unsigned int SNAPLEN = 65536;
int ETHERNET_HEADER_LENGTH = 14;


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


void got_packet(std::uint8_t *args, const struct pcap_pkthdr *header,
                const std::uint8_t *pkt_data) {
    std::uint8_t *packet_end = (std::uint8_t * )(pkt_data + header->len);

    ip_header *ih;
    udp_header *uh;
    dns_header *dh;
    std::uint32_t ip_len;
    std::uint16_t sport, dport;

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + ETHERNET_HEADER_LENGTH); //length of ethernet header

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

    /* print ip addresses and udp ports */
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
    printf("QR: %d qdcount: %d ancount: %d nscount: %d arcount: %d\n", dh->qr, dh->qdcount, dh->ancount, dh->nscount,
           dh->arcount);

    std::uint8_t *question_data = (std::uint8_t * )((std::uint8_t *) dh + sizeof(dns_header));

    for (int i = 0; i < dh->qdcount; i++) {
        std::string domain_name;
        while (question_data < packet_end && (*question_data & 0b11000000) == 0) {
            int label_length = *question_data;
            if (label_length == 0) {
                break;
            }
            std::cout << "label " << i << " found, data should be " << label_length << " long: ";

            if (question_data + 1 + label_length < packet_end) {
                std::string label(question_data + 1, question_data + 1 + label_length);
                std::cout << label << std::endl;

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
            std::cout << "domain: " << domain_name << " QTYPE: " << (int) qtype << std::endl;
        } else {
            std::cerr << "packet corrupted, qtype and qclass is missing" << std::endl;
            return;
        }
    }

    std::cout << "read until: " << (void *) question_data << " packet length: " << (void *) packet_end << "  diff: "
              << (void *) (packet_end - question_data) << std::endl;

}


int main(int argc, char *argv[]) {

    if (argc != 4) {
        std::cout << "usage: wakeondns DEVICE HOSTNAME MACADDRESS" << std::endl;
        return 0;
    }

    char *dev = argv[1];
    std::string dnsname = std::string(argv[2]);
    std::string macaddress = std::string(argv[3]);

    std::cout << "listening on \"" << dev << "\"" << std::endl;
    std::cout << "waking " << dnsname << " (" << macaddress << ")" << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp and port 53 and (udp[10] & 128 = 0)";  //only dns querys, no responses (qr bit)
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *handle;
    struct pcap_pkthdr header;    /* The header that pcap gives us */
    const std::uint8_t *packet;        /* The actual packet */
    std::uint8_t *user_data = NULL;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, SNAPLEN, 1, READ_TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "This program works only on Ethernet networks.\n");
        return -1;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    if (pcap_loop(handle, -1, got_packet, user_data) != 0) {
        fprintf(stderr, "error from  pcap_loop: %s\n", pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);

    return 0;
}
