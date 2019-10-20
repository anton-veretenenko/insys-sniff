#ifndef FILTER_H
#define FILTER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define MAX_FILTERS 16

enum FilterIpType {
    ipv4, ipv6
};
enum FilterProtoType {
    tcp, udp
};

typedef struct Filter_t {
    enum FilterIpType type;
    enum FilterProtoType proto_type;
    uint32_t ip4;
    uint8_t ip6[16];
    uint16_t port;
} Filter;

struct Filters_t {
    Filter *filters;
    uint8_t count;
} filters;

// init filters from command line and/or config file
bool filters_init(int argc, char *argv[]);
void filters_clear();
bool filter_add(enum FilterIpType type, enum FilterProtoType proto_type,
                uint32_t ip4, uint8_t ip6[16], uint16_t port);

#endif