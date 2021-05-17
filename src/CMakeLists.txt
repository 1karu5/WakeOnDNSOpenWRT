cmake_minimum_required(VERSION 3.15)
project(wakeondns)

set(CMAKE_CXX_STANDARD 17)

include(FindPCAP.cmake)

add_executable(wakeondns main.cpp)
target_link_libraries(wakeondns ${PCAP_LIBRARY})
INSTALL(TARGETS wakeondns RUNTIME DESTINATION /usr/bin/)
