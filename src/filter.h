#ifndef FILTER_H
#define FILTER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "parser.h"

#define MAX_FILTERS 16

enum FilterIpType {
    ipv4, ipv6
};

typedef struct Filter_t {
    enum FilterIpType type;
    uint8_t protocol;
    uint32_t ip4;
    uint8_t ip6[16];
    uint16_t port;
} Filter;

struct Filters_t {
    Filter *filters;
    uint8_t count;
} filters;

void filters_clear();
bool filter_add(enum FilterIpType type, uint8_t protocol,
                uint32_t ip4, uint8_t ip6[16], uint16_t port);
bool filter_pass_v46(const packet_v46 *packet);
bool filter_parse_from_args(char *optarg);
bool filter_parse_json_object(char *json);
bool filters_parse_from_file(const char *filename, char *device);

#endif