#include "parser.h"

bool parser_parse_v4(const char *buf, packet_v4 *packet)
{
    // check ethernet header
    struct ethhdr *eth_header = (struct ethhdr *)buf;
    if (ntohs(eth_header->h_proto) != ETH_P_IP) {
        return false; // drop non ip packets
    } // TODO: ipv6 proto handling

    memset(packet, 0, sizeof(packet_v4));

    // parse ip header
    struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ethhdr));
    struct in_addr s,d;
    s.s_addr = ip_header->saddr;
    d.s_addr = ip_header->daddr;
    packet->ip_from = ip_header->saddr;
    packet->ip_to = ip_header->daddr;
    packet->protocol = ip_header->protocol;
    packet->size = ntohs(ip_header->tot_len);

    int ip_header_length = ip_header->ihl * 4;

    // fill ports for tcp & udp
    if (packet->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header =
            (struct tcphdr *)(buf + sizeof(struct ethhdr) + ip_header_length);
        packet->port_from = ntohs(tcp_header->source);
        packet->port_to = ntohs(tcp_header->dest);
    } else
    if (packet->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header =
            (struct udphdr *)(buf + sizeof(struct ethhdr) + ip_header_length);
        packet->port_from = ntohs(udp_header->source);
        packet->port_to = ntohs(udp_header->dest);
    } else {
        packet->port_from = 0;
        packet->port_to = 0;
    }

    return true;
}