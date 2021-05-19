#include <iostream>
#include <string>
#include "Awakener.h"
#include "PacketListener.h"


int main(int argc, char *argv[]) {

    if (argc != 5) {
        std::cout << "usage: wakeondns LISTENDEVICE SENDDEVICE HOSTNAME MACADDRESS " << std::endl;
        return 0;
    }

    char* listendev = argv[1];
    char* senddev = argv[2];
    char* hostname = argv[3];
    char* macaddress = argv[4];

    Awakener awaker(senddev);

    awaker.add(hostname, macaddress);

    PacketListener p(&awaker, listendev, "udp and port 53 and (udp[10] & 128 = 0)");

    p.run();

    return 0;
}
