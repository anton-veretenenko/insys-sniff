#ifndef SIPV4_H
#define SIPV4_H

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
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>

struct socket_v4_t {
    int sock;
} socket_v4;

bool socketv4_init(const char *device);
void socketv4_clear();
int socketv4_read(uint8_t *buf, uint16_t size);


#endif