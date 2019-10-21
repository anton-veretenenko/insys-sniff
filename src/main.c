#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include "filter.h"
#include "sock.h"
#include "parser.h"

static int int_signal = 0;
static char net_device[IF_NAMESIZE];
static const char *options = "d:f:h?";
extern char *optarg;

void int_signal_handler(int signal)
{
    int_signal = signal;
    printf("\nTerminating...\n");
}

void print_usage()
{
    printf("\nUsage: insys-sniff -d eth0 [-f t,127.0.0.1,80 -f u,0.0.0.0,53]\n");
}

bool read_config(int argc, char *argv[])
{
    char opt;
    bool device_set = false;
    bool filters_set = false;
    bool help_called = false;
    filters_clear();
    
    while ((opt = getopt(argc, argv, options)) != -1) {
        switch (opt) {
            case 'd':
                if (!device_set) {
                    strcpy(net_device, optarg);
                    device_set = true;
                } else {
                    printf("No multiple interfaces allowed, using first one.\n");
                }
                break;
            case 'f':
                printf("Filter %s\n", optarg);
                if (filter_parse_from_args(optarg)) {
                    filters_set = true;
                }
                break;
            case 'h':
            case '?':
                help_called = true;
                break;
            default:
                break;
        }
    }

    // TODO: read from config file

    if (!device_set) {
        // try to parse config file
        if (!filters_parse_from_file("config.json", net_device)) {
            printf("Config file parse failed\n");
            print_usage();
            return false;
        }
    }

     return true;

}

void print_packet_line(packet_v46 *packet)
{
    struct in_addr from, to;
    from.s_addr = packet->ip_from;
    to.s_addr = packet->ip_to;
    char from_a[INET_ADDRSTRLEN], to_a[INET_ADDRSTRLEN];
    char from_a6[INET6_ADDRSTRLEN], to_a6[INET6_ADDRSTRLEN];

    if (packet->is_ipv6 != 1) {
        // ipv4 print
        strcpy(from_a, inet_ntoa(from));
        strcpy(to_a, inet_ntoa(to));

        //float size = packet->size / 1024;
        printf("%s:%d\t %s:%d\t %d\t %d b\n",
            from_a,
            packet->port_from,
            to_a,
            packet->port_to,
            packet->protocol,
            packet->size
        );
    } else {
        // ipv6 print
        inet_ntop(AF_INET6, packet->ip_from_6, from_a6, sizeof(from_a6));
        inet_ntop(AF_INET6, packet->ip_to_6, to_a6, sizeof(to_a6));

        //float size = packet->size / 1024;
        printf("%s:%d\t %s:%d\t %d\t %d b\n",
            from_a6,
            packet->port_from,
            to_a6,
            packet->port_to,
            packet->protocol,
            packet->size
        );
    }
}

void sniff_loop()
{
    uint8_t *buf = malloc(2048);
    fd_set fd_mask;
    struct timeval timeout;
    int selected = 0;

    while (true) {
        if (int_signal != 0) {
            free(buf);
            return;
        }

        FD_ZERO(&fd_mask);
        FD_SET(socket_v46.sock, &fd_mask);
        timeout.tv_usec = 0;
        timeout.tv_sec = 3;
        selected = select(socket_v46.sock+1, &fd_mask, NULL, NULL, &timeout);
        if (selected == -1) {
            if (!int_signal) {
                perror("select()");
            }
            break;
        }

        if (FD_ISSET(socket_v46.sock, &fd_mask)) {
            int size = socket_read(buf, 2048);
            if (size < 0) {
                perror("recv()");
                return;
            } else {
                packet_v46 packet;
                if (parser_parse_v46(buf, &packet)) {
                    // parsed, expecting good data in packet struct
                    if (filter_pass_v46(&packet)) {
                        // packet passed filters
                        // print it out
                        print_packet_line(&packet);
                    }
                } //else printf("packet failed to parse\n");
            }
        }
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, int_signal_handler); // handle ctrl+c terminate signal

    if (!read_config(argc, argv)) {
        return -1;
    }

    if (!socket_init(net_device)) {
        return -1;
    }

    sniff_loop();

    socket_clear();

    return 0;
}
