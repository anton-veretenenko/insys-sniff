#include "parser.h"

bool parser_parse_v46(const char *buf, packet_v46 *packet)
{
    // check ethernet header
    struct ethhdr *eth_header = (struct ethhdr *)buf;
    if (ntohs(eth_header->h_proto) != ETH_P_IP &&
        ntohs(eth_header->h_proto) != ETH_P_IPV6) {
        return false; // drop non ip packets
    }
    memset(packet, 0, sizeof(packet_v46));
    int ip_header_length = 0;

    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        // parse ip header
        struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ethhdr));
        struct in_addr s,d;
        s.s_addr = ip_header->saddr;
        d.s_addr = ip_header->daddr;
        packet->ip_from = ip_header->saddr;
        packet->ip_to = ip_header->daddr;
        packet->protocol = ip_header->protocol;
        packet->size = ntohs(ip_header->tot_len);
        ip_header_length = ip_header->ihl * 4;
    } else
    if (ntohs(eth_header->h_proto) == ETH_P_IPV6) {
        // parse ipv6 header
        packet->is_ipv6 = 1;
        struct ip6_hdr *ip_header = (struct ip6_hdr *)(buf + sizeof(struct ethhdr));
        memcpy(packet->ip_to_6, &ip_header->ip6_dst, sizeof(struct in6_addr));
        memcpy(packet->ip_from_6, &ip_header->ip6_src, sizeof(struct in6_addr));
        packet->protocol = ip_header->ip6_nxt;
        packet->size = ntohs(ip_header->ip6_plen) + sizeof(struct ethhdr) + sizeof(struct ip6_hdr);
        ip_header_length = sizeof(struct ip6_hdr);
    } else {
        return false;
    }
    
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