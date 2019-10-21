#include "filter.h"

void filters_clear()
{
    if (filters.count > 0) {
        free(filters.filters);
        filters.count = 0;
    }
}

bool filter_add(enum FilterIpType type, uint8_t protocol,
                uint32_t ip4, uint8_t ip6[16], uint16_t port)
{
    if (filters.count < MAX_FILTERS) {
        Filter *filters_p = malloc(sizeof(Filter) * (filters.count+1));
        if (filters.count > 0) {
            memcpy(filters_p, filters.filters, sizeof(Filter) * filters.count);
            free(filters.filters);
        }
        Filter *filter = filters_p + filters.count;
        filter->type = type;
        filter->protocol = protocol;
        filter->ip4 = ip4;
        if (type == ipv6) {
            memcpy(filter->ip6, ip6, sizeof(filter->ip6));
        }
        filter->port = port;
        filters.filters = filters_p;
        filters.count++;

        return true;
    }

    return false;
}

bool filter_parse_from_args(char *optarg)
{
    char *substr = strtok(optarg, ",");
    if (substr != NULL) {
        Filter filter;
        memset(&filter, 0, sizeof(filter));

        if (strcasecmp(substr, "t") == 0) {
            filter.protocol = IPPROTO_TCP;
        } else
        if (strcasecmp(substr, "u") == 0) {
            filter.protocol = IPPROTO_UDP;
        } else
        {
            printf("\n wrong type\n");
            return false;
        }
        
        substr = strtok(NULL, ",");
        if (substr != NULL) {
            if (inet_pton(AF_INET, substr, &filter.ip4) == 1) {
                // ipv4 success conversion
                filter.type = ipv4;
            } else
            if (inet_pton(AF_INET6, substr, filter.ip6) == 1) {
                // ipv6 success conversion
                filter.type = ipv6;
            } else {
                printf(" bad ip\n");
                return false;
            }

            // ip parsed, type set
            substr = strtok(NULL, ",");
            if (substr != NULL) {
                filter.port = atoi(substr);
            } else {
                printf(" missing port\n");
                return false;
            }
        } else {
            printf(" misssing ip\n");
            return false;
        }

        filter_add(filter.type, filter.protocol, filter.ip4, filter.ip6, filter.port);
    }

    return true;
}

bool filter_pass_v4(const packet_v4 *packet)
{
    if (filters.count == 0) {
        return true;
    }

    for (int i = 0; i < filters.count; i++) {
        Filter *filter = filters.filters + i;
        if (filter->type == ipv4 &&
            packet->protocol == filter->protocol) {
            if (filter->ip4 != 0) {
                // check ip also
                if (packet->ip_from != filter->ip4 &&
                    packet->ip_to != filter->ip4) {
                        // source and dest ip did not match
                        // TODO: only source ip match needed
                        continue;
                }
            }
            if (filter->port != 0) {
                // check port also
                if (packet->port_from != filter->port &&
                    packet->port_to != filter->port) {
                        // port did not match source or dest
                        continue;
                }
            }
            // filter passed, no need to check others
            return true;
        } else {
            // protocol did not match
            continue;
        }
    }

    return false;
}