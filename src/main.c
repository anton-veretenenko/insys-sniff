#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include "filter.h"
#include "sipv4.h"

static int int_signal = 0;

void int_signal_handler(int signal)
{
    int_signal = signal;
}

void sniff_loop()
{
    while (true) {
        if (int_signal != 0) {
            return;
        }

        // process socket reads
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, int_signal_handler); // handle ctrl+c terminate signal

    filters_init(argc, argv);
    if (!socketv4_init("enp0s3")) {
        return -1;
    }

    sniff_loop();

    socketv4_clear();

    return 0;
}
