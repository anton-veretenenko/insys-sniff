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
#include "sipv4.h"

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
                filters_init_from_args(optarg);
                filters_set = true;
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

    if (!device_set || help_called) {
        print_usage();
        return false;
    }

     return true;

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
        FD_SET(socket_v4.sock, &fd_mask);
        timeout.tv_usec = 0;
        timeout.tv_sec = 3;
        selected = select(socket_v4.sock+1, &fd_mask, NULL, NULL, &timeout);
        if (selected == -1) {
            if (!int_signal) {
                perror("select()");
            }
            break;
        } else
        if (selected == 0) {
            printf(".");
        }

        if (FD_ISSET(socket_v4.sock, &fd_mask)) {
            int size = socketv4_read(buf, 2048);
            if (size < 0) {
                perror("recv()");
            } else {
                //printf("s:%d:", size);
                // TODO: parse packet
                // parse_packet(buf, size);
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

    if (!socketv4_init(net_device)) {
        return -1;
    }

    sniff_loop();

    socketv4_clear();

    return 0;
}
