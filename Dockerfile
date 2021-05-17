
FROM openwrtorg/sdk:mips_24kc-openwrt-19.07

RUN mkdir -p /home/build/openwrt/bin


RUN cd /home/build/openwrt/ && ./scripts/feeds update base && make defconfig && ./scripts/feeds install libpcap

RUN mkdir -p /home/build/openwrt/package/wakeondns/src
RUN mkdir -p /home/build/openwrt/package/wakeondns/files
COPY --chown=build Makefile /home/build/openwrt/package/wakeondns/
COPY --chown=build src /home/build/openwrt/package/wakeondns/src
COPY --chown=build files /home/build/openwrt/package/wakeondns/files

RUN cd /home/build/openwrt/ && ./scripts/feeds install wakeondns

CMD bash -c "make package/wakeondns/compile -j1 V=s"
