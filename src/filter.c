#include "filter.h"
#include "../jsmn/jsmn.h"

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

bool filter_parse_from_args(char *optarg)
{
    char *substr = strtok(optarg, ",");
    uint8_t proto = 0;
    if (substr != NULL) {
        Filter filter;
        memset(&filter, 0, sizeof(filter));

        if (strcasecmp(substr, "t") == 0) {
            filter.protocol = IPPROTO_TCP;
        } else
        if (strcasecmp(substr, "u") == 0) {
            filter.protocol = IPPROTO_UDP;
        } else
        if ((proto = atoi(substr)) != 0) {
            filter.protocol = proto;
        } else {
            printf("\n wrong protocol\n");
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

bool filter_parse_json_object(char *json)
{
    jsmn_parser p;
    jsmntok_t t[8];
    jsmn_init(&p);
    int r = jsmn_parse(&p, json, strlen(json), t, 8);
    if (r < 7) {
        printf("Config: filter object parse error %d\n", r);
        return false;
    }

    Filter filter;
    memset(&filter, 0, sizeof(filter));
    bool proto_set = false;
    bool ip_set = false;
    bool port_set = false;
    uint8_t proto = 0;

    for (int i = 1; i < r; i++) {
        json[t[i].end] = 0;
        if (strcasecmp(json + t[i].start, "protocol") == 0) {
            i++;
            json[t[i].end] = 0;
            if (strcasecmp(json + t[i].start, "tcp") == 0) {
                filter.protocol = IPPROTO_TCP;
            } else
            if (strcasecmp(json + t[i].start, "udp") == 0) {
                filter.protocol = IPPROTO_UDP;
            } else
            if ((proto = atoi(json + t[i].start)) != 0) {
                filter.protocol = proto;
            } else {
                printf("Config: filter protocol parse error\n");
                return false;
            }
            proto_set = true;
        } else
        if (strcasecmp(json + t[i].start, "ip") == 0) {
            i++;
            json[t[i].end] = 0;
            if (inet_pton(AF_INET, json + t[i].start, &filter.ip4) == 1) {
                // ipv4 success conversion
                filter.type = ipv4;
            } else
            if (inet_pton(AF_INET6, json + t[i].start, filter.ip6) == 1) {
                // ipv6 success conversion
                filter.type = ipv6;
            } else {
                printf("Config: filter ip parse error\n");
                return false;
            }
            ip_set = true;
        } else
        if (strcasecmp(json + t[i].start, "port") == 0) {
            i++;
            json[t[i].end] = 0;
            filter.port = atoi(json + t[i].start);
            port_set = true;
        }
    }

    if (proto_set && ip_set && port_set) {
        filter_add(filter.type, filter.protocol, filter.ip4, filter.ip6, filter.port);
        return true;
    }

    return false;
}

bool filters_parse_from_file(const char *filename, char *device)
{
    printf("Reading config from file.\n");

    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        perror("fopen()");
        return false;
    }

    fseek(f, 0, SEEK_END);
    uint32_t filesize = ftell(f);
    rewind(f);
    if (filesize > 1024*10*10) {
        fclose(f);
        printf("Config: file is too big\n");
        return false;
    }

    char *buffer = malloc(filesize);
    uint32_t read = fread(buffer, 1, filesize, f);
    if (read != filesize) {
        fclose(f);
        printf("Config: read error\n");
        return false;
    }
    fclose(f);

    int r;
    jsmn_parser p;
    const int tokens = 128;
    jsmntok_t t[tokens];
    jsmn_init(&p);
    r = jsmn_parse(&p, buffer, filesize, t, tokens);
    if (r < 0) {
        printf("Config: JSON parse error %d\n", r);
        return false;
    }

    if (r < 1 || t[0].type != JSMN_OBJECT) {
        printf("Config: JSON should be main object\n");
        return false;
    }

    for (int i = 1; i < r; i++) {
        if (t[i].type == JSMN_STRING) {
            buffer[t[i].end] = 0; // terminate string for ease of use
            if (strcasecmp(buffer + t[i].start, "device") == 0) {
                // device setting
                i++;
                buffer[t[i].end] = 0;
                strcpy(device, buffer + t[i].start);
            } else
            if (strcasecmp(buffer + t[i].start, "filters") == 0) {
                // filters array detected
                i++;
                if (t[i].type == JSMN_ARRAY && t[i+1].type == JSMN_OBJECT) {
                    int filters_array_size = t[i].size;
                    for (int j = 0; j < filters_array_size; j++) {
                        // parse filter objects
                        buffer[t[i+1].end] = 0;
                        if (!filter_parse_json_object(buffer + t[i+1].start)) {
                            printf("Config: fail to parse filter object\n");
                            return false;
                        }
                        i += 7;
                    }
                } else {
                    printf("Config: filters should be in an array\n");
                }
            }
        }
    }

    return true;
}