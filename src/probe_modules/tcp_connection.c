#include "tcp_connection.h"

#include "../../lib/includes.h"
#include "../../lib/pbm.h"
#include "../lib/logger.h"
#include "packet.h"


/*
 * Given an Eth/IPv4/TCP packet it creates an ack for the TCP packet
 * to the source of the packet
 *
 * The resulting packet is written to buf which has space for at most max_len bytes
 *
 * Returns: size of the packet written to buf
 */
uint32_t tcp_buildAck(const uint8_t *packet, uint8_t* buf, uint32_t max_len) {
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
                    + 4*ip_hdr->ip_hl);

    int payload =  ntohs(ip_hdr->ip_len) - (sizeof(struct ip) + tcp->th_off*4);
    if((tcp->th_flags & TH_SYN || tcp->th_flags & TH_FIN) && payload==0) {
        payload=1;
    }

    uint32_t size = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
	
	if (size > max_len)
		return 0;
	
    struct ip *ip_hdrs = (struct ip *)&buf[sizeof(struct ether_header)];
    struct tcphdr *tcps = (struct tcphdr*)((char *)ip_hdrs + 4*ip_hdrs->ip_hl);
    tcps->th_seq = tcp->th_ack;
    tcps->th_ack = htonl(ntohl(tcp->th_seq)+payload);
    ip_hdrs->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    tcps->th_off = 5;
    tcps->th_flags = TH_ACK;
    ip_hdrs->ip_dst = ip_hdr->ip_src;
    ip_hdrs->ip_src = ip_hdr->ip_dst;
    tcps->th_sport = tcp->th_dport;
    tcps->th_dport = tcp->th_sport;
    tcps->th_win = htons(65535);

    tcps->th_sum = 0;
    tcps->th_sum = tcp_checksum(sizeof(struct tcphdr),
            ip_hdrs->ip_src.s_addr, ip_hdrs->ip_dst.s_addr, tcps);

    ip_hdrs->ip_sum = 0;
    ip_hdrs->ip_sum = zmap_ip_checksum((unsigned short *) ip_hdrs);
	
    return size;
}



uint32_t tcp_buildAck_with_acknum(const uint8_t *packet, uint32_t ack_num, uint8_t* buf, uint32_t max_len) {
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
                                          + 4*ip_hdr->ip_hl);
    
    int payload =  ntohs(ip_hdr->ip_len) - (sizeof(struct ip) + tcp->th_off*4);
    if((tcp->th_flags & TH_SYN || tcp->th_flags & TH_FIN) && payload==0) {
        payload=1;
    }
    
    uint32_t size = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
    
    if (size > max_len)
        return 0;
    
    struct ip *ip_hdrs = (struct ip *)&buf[sizeof(struct ether_header)];
    struct tcphdr *tcps = (struct tcphdr*)((char *)ip_hdrs + 4*ip_hdrs->ip_hl);
    tcps->th_seq = tcp->th_ack;
    tcps->th_ack = htonl(ntohl(tcp->th_seq)+payload);
    ip_hdrs->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    tcps->th_off = 5;
    tcps->th_flags = TH_ACK;
    ip_hdrs->ip_dst = ip_hdr->ip_src;
    ip_hdrs->ip_src = ip_hdr->ip_dst;
    tcps->th_sport = tcp->th_dport;
    tcps->th_dport = tcp->th_sport;
    
    tcps->th_sum = 0;
    tcps->th_sum = tcp_checksum(sizeof(struct tcphdr),
                                ip_hdrs->ip_src.s_addr, ip_hdrs->ip_dst.s_addr, tcps);
    
    ip_hdrs->ip_sum = 0;
    ip_hdrs->ip_sum = zmap_ip_checksum((unsigned short *) ip_hdrs);
    
    return size;
}



/*
 * Given an ETH/IPv4/TCP packet this function creates an appropriate RST
 * packet
 *
 * The resulting packet is written to buf which has space for at most max_len bytes
 *
 * Returns: size of the packet written to buf
 */
uint32_t tcp_buildRst(const uint8_t *packet, uint8_t* buf, uint32_t max_len) {
    uint32_t size = tcp_buildAck(packet, buf, max_len);

    struct ip *ip_hdr = (struct ip *)&buf[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr + 4*ip_hdr->ip_hl);

    tcp->th_flags = TH_RST;
	tcp->th_ack = 0;
    tcp->th_sum = 0;
    tcp->th_win = 0;
    tcp->th_sum = tcp_checksum(sizeof(struct tcphdr),
            ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr, tcp);

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = zmap_ip_checksum((unsigned short *) ip_hdr);
    return size;
}

/*
 * Given a ETH/IPv4/TCP packet returns the length
 * of the TCP payload in bytes
 *
 */
uint32_t tcp_getPayloadLength(const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr + 4*ip_hdr->ip_hl);

	// IP_LEN is header + payload, so remove IP and TCP header to get TCP payload
    int payload = ntohs(ip_hdr->ip_len) - (4*ip_hdr->ip_hl) - (tcp->th_off*4);
    //log_debug("tcp_connection", "%u - %u - %u",ntohs(ip_hdr->ip_len), sizeof(struct ip), tcp->th_off*4);
    return payload;
}
