#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <signal.h>

#define BUFFER_SIZE 1514
