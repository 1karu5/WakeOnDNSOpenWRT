#!/bin/bash

docker build . -t wakeondns

docker run --rm -v "$(pwd)"/bin/:/home/build/openwrt/bin wakeondns
