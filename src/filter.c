#include "filter.h"

void filters_clear()
{
    if (filters.count > 0) {
        free(filters.filters);
        filters.count = 0;
    }
}

bool filter_add(enum FilterIpType type, enum FilterProtoType proto_type,
                uint32_t ip4, uint8_t ip6[16], uint16_t port)
{
    if (filters.count < MAX_FILTERS) {
        Filter *filters_p = malloc(sizeof(Filter) * filters.count+1);
        if (filters.count > 0) {
            memcpy(filters_p, filters.filters, sizeof(Filter) * filters.count);
            free(filters.filters);
        }
        Filter *filter = &(filters_p[filters.count+1]);
        filter->type = type;
        filter->proto_type = proto_type;
        filter->ip4 = ip4;
        if (type == ipv6) {
            memcpy(filter->ip6, ip6, sizeof(filter->ip6));
        }
        filter->port = port;
        filters.filters = filters_p;
        filters.count++;
    }
}

bool filters_init_from_args(const char *optarg)
{
    filters.count = 0;
    printf("filters_init_from_args\n");
}