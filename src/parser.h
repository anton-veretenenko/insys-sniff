#ifndef PARSER_H
#define PARSER_H

#include <features.h>

// to make vscode see __USE_MISC for tcp headers
//#ifndef _DEFAULT_SOURCE
//#define _DEFAULT_SOURCE
//#endif
//#ifndef __USE_MISC
//#define __USE_MISC
//#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>

typedef struct packet_v4_t {
    uint32_t ip_from;
    uint16_t port_from;
    uint32_t ip_to;
    uint16_t port_to;
    uint8_t protocol;
    uint16_t size;
} packet_v4;


bool parser_parse_v4(const char *buf, packet_v4 *packet);

#endif