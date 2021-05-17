#include <iostream>
#include <pcap.h>


int READ_TIMEOUT = 10;
int SNAPLEN = 65536;

int main(int argc, char *argv[]) {

    if(argc != 4){
        std::cout << "usage: wakeondns DEVICE HOSTNAME MACADDRESS" << std::endl;
        return (1);
    }

    char *dev = argv[1];
    char *dnsname = argv[2];
    char *macaddress = argv[3];

    std::cout << "listening on \"" << dev << "\"" << std::endl;
    std::cout << "waking" << dnsname << "(" << macaddress << ")" << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp and port 53";
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
        return (2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);

    return 0;
}