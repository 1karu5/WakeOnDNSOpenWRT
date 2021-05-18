
#include "Awakener.h"


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include <iostream>
#include <sstream>
#include <utility>
#include <vector>

#define PACKET_BUF         17*6
#define REMOTE_ADDR        "255.255.255.255"
#define REMOTE_PORT        9

Awakener::Awakener(std::string interface_name) : interface_name_(std::move(interface_name)) {
    open_socket_ = start_socket();
}

Awakener::~Awakener() {
    std::cout << "close socket" << std::endl;
    close(open_socket_);
}

void Awakener::wake(const std::string &name) {
    if (hosts_.count(name)) {
        std::cout << "waking " << name << " with mac " << hosts_.at(name) << std::endl;
        send_wol(hosts_.at(name));
    }
}

void Awakener::add(const std::string &name, const std::string &mac) {
    std::cout << "adding " << name << " (" << mac << ") to wake list" << std::endl;
    hosts_.emplace(name, mac);
}

int Awakener::start_socket() {
    int sock;
    int optval = 1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "Cannot open socket: %s ...!\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name_.c_str(), interface_name_.size()) < 0) {
        fprintf(stderr, "Cannot set socket options: %s ...!\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *) &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "Cannot set socket options: %s ...!\n", strerror(errno));
        return -1;
    }

    return sock;
}

void Awakener::send_wol(const std::string &mac) {

    unsigned char packet[PACKET_BUF];
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REMOTE_PORT);

    auto split_mac = split(mac, ':');
    unsigned char mac_addr[6];
    for (int i = 0; i < split_mac.size(); i++) {
        mac_addr[i] = (unsigned char) strtol(split_mac[i].c_str(), nullptr, 16);
    }

    if (inet_aton(REMOTE_ADDR, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid remote ip address given ...!\n");
        return;
    }

    for (int i = 0; i < 6; i++) {
        packet[i] = 0xFF;
    }

    for (int i = 1; i <= 16; i++) {
        for (int j = 0; j < 6; j++) {
            packet[i * 6 + j] = mac_addr[j];
        }
    }

    if (sendto(open_socket_, packet, sizeof(packet), 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot send data: %s ...!\n", strerror(errno));
        return;
    }
}

std::vector<std::string> Awakener::split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream stream(s);
    while (std::getline(stream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}


