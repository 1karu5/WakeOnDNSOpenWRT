#include <iostream>
#include <string>
#include "Awakener.h"
#include "PacketListener.h"


int main(int argc, char *argv[]) {

    if (argc < 4 || argc % 2 != 0) {
        std::cout << "usage: wakeondns DEVICE HOSTNAME MACADDRESS HOSTNAME MACADDRESS ..." << std::endl;
        return 0;
    }

    char *dev = argv[1];

    Awakener awaker(dev);

    for (int i = 2; i < argc; i += 2) {
        awaker.add(std::string(argv[i]), std::string(argv[i + 1]));
    }

    PacketListener p(&awaker, dev, "udp and port 53 and (udp[10] & 128 = 0)");

    p.run();

    return 0;
}
