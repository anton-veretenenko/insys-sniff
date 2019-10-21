#include "sipv4.h"

bool socketv4_init(const char *device)
{
    int sock;
    socket_v4.sock = 0;
    struct sockaddr_ll sockaddr;
    struct packet_mreq mreq;

    int idx = if_nametoindex(device);
    if (idx == 0) {
        perror("if_nametoindex()");
        return false;
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket()");
        return false;
    }
    socket_v4.sock = sock;
    
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_ifindex = idx;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1) {
        perror("bind()");
        close(sock);
        return false;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = idx;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
        perror("setsockopt()");
        close(sock);
        return false;
    }

    return true;
}

void socketv4_clear()
{
    if (socket_v4.sock != 0) {
        close(socket_v4.sock);
    }
}

int socketv4_read(uint8_t *buf, uint16_t size)
{
    if (socket_v4.sock == 0) {
        return -1;
    }

    return recv(socket_v4.sock, buf, size, 0);
}