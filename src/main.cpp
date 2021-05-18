#include <iostream>
#include <pcap.h>


int READ_TIMEOUT = 10;
unsigned int SNAPLEN = 65536;


/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;


typedef struct dns_header{      // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    std::uint16_t id;
    bool qr : 1;
    unsigned int opcode : 4;
    bool aa : 1;
    bool tc : 1;
    bool rd : 1;
    bool ra : 1;
    unsigned int z : 3;
    unsigned int rcode : 4;
    std::uint16_t qdcount;
    std::uint16_t ancount;
    std::uint16_t nscount;
    std::uint16_t arcount;
}dns_header;


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *pkt_data){
    printf("Jacked a packet with length of [%d]\n", header->len);


    //struct tm ltime;
    //char timestr[16];
    ip_header *ih;
    udp_header *uh;
    dns_header *dh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    //localtime_s(&ltime, &local_tv_sec);
    //strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    /* print timestamp and length of the packet */
    //printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data +
                        14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    dh = (dns_header *) ((u_char*)uh + 8);

    /* print ip addresses and udp ports */
    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
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
}


int main(int argc, char *argv[]) {

    std::cout << "u_short" << sizeof(u_short) << std::endl;
    std::cout << "u_int" << sizeof(u_int) << std::endl;
    std::cout << "u_char" << sizeof(u_char) << std::endl;
    std::cout << "udp_header" << sizeof(udp_header) << std::endl;
    std::cout << "dns_header" << sizeof(dns_header) << std::endl;
    std::cout << "ip_header" << sizeof(ip_header) << std::endl;
    std::cout << "ip_address" << sizeof(ip_address) << std::endl;



    if(argc != 4){
        std::cout << "usage: wakeondns DEVICE HOSTNAME MACADDRESS" << std::endl;
        return (1);
    }

    char *dev = argv[1];
    char *dnsname = argv[2];
    char *macaddress = argv[3];

    std::cout << "listening on \"" << dev << "\"" << std::endl;
    std::cout << "waking " << dnsname << " (" << macaddress << ")" << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp and port 53 and (udp[10] & 128 = 0)";  //only dns querys
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *handle;
    struct pcap_pkthdr header;    /* The header that pcap gives us */
    const u_char *packet;        /* The actual packet */

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
    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr,"This program works only on Ethernet networks.\n");
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

    if(pcap_loop(handle, -1, got_packet, NULL) != 0){
        fprintf(stderr, "error from  pcap_loop: %s\n", pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);

    return 0;
}
