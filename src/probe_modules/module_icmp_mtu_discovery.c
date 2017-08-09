// probe module for performing HTTP initial window scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netpacket/packet.h>

#include "probe_modules.h"
#include "packet.h"
#include "../../lib/includes.h"
#include "../../lib/pbm.h"
#include "../fieldset.h"
#include "../state.h"
#include "../output_modules/output_modules.h"

#include "../ringbuffer.h"
#include "../lib/logger.h"

#include "../recv.h"
#include "state_machine.h"
#include "tcp_connection.h"
#include "ipdata.h"
#include "validate.h"

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


// this should probably be determined using ioctl once
#define LOCAL_MTU (1500)

// where do you want to start probing? In our network, 8 hops until we leave the DFN network which is capable of 1,5k mtu
#define START_TTL (255)


struct path_data {
	struct {
		struct in_addr ip;
		uint16_t mtu;
	} host[255];
	unsigned char next;
};

probe_module_t module_icmp_mtu_discovery;
static uint32_t num_ports;


int icmp_path_discovery_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	
	// init state machine
	uint32_t statesize = zconf.rate*10; // initialize the statetable according to rate
	if(statesize < 10000) {
		statesize = 10000;
	}
	state_myinit(statesize, 20);
	
	
	return EXIT_SUCCESS;
}

int icmp_path_discovery_init_perthread(void* buf, macaddr_t *src,
									   macaddr_t *gw, port_h_t dst_port, __attribute__((unused))void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + 4);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	make_udp_header(udp_header, dst_port, LOCAL_MTU - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct udphdr));
	return LOCAL_MTU;
}


void icmp_path_discovery_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int icmp_path_discovery_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
								 __attribute__((unused)) uint32_t *validation, __attribute__((unused)) int probe_num, __attribute__((unused))void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	
	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_off |= htons(IP_DF);
	ip_header->ip_p = IPPROTO_UDP;
	ip_header->ip_ttl = START_TTL;
	
	unsigned int payload_len = LOCAL_MTU - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct udphdr);
	
	// Update the IP and UDP headers to match the new payload length
	ip_header->ip_len   = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_len);
	udp_header->uh_ulen = ntohs(sizeof(struct udphdr) + payload_len);
	
	
	memset((char*)&udp_header[1], 0, payload_len);
	
	
	// if sum == 0 -> IPv4 will ignore the UDP checksum
	udp_header->uh_sum = 0;
	udp_header->uh_sport = htons(get_src_port(num_ports,
											  probe_num, validation));
	
	
	
	alias_unsigned_short *src_addr = (alias_unsigned_short *) &src_ip;
	alias_unsigned_short *dest_addr = (alias_unsigned_short *) &dst_ip;
	
	// calculate udp checksum... which is with only 0 as payload is only the pseudo header
	unsigned long sum = 0;
	sum += src_addr[0];
	sum += src_addr[1];
	sum += dest_addr[0];
	sum += dest_addr[1];
	sum += htons(IPPROTO_UDP);
	sum += udp_header->uh_ulen;
	sum += udp_header->uh_sport;
	sum += udp_header->uh_dport;
	sum += udp_header->uh_ulen;
	//	sum += udp_header->uh_sum;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	
	udp_header->uh_sum = (u_short)~sum;
	
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);
	return EXIT_SUCCESS;
}


#define ICMP_SMALLEST_SIZE 5
int icmp_path_discovery_validate_packet(const struct ip *ip_hdr, uint32_t len,
										uint32_t *src_ip,
									 uint32_t *validation)
{
	// we should get an ICMP packet as a return or a UDP packet
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return 0;
	}
	
	if (((uint32_t) 4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
		// buffer not large enough to contain expected icmp header
		return 0;
	}
	
	
	struct icmp* icmp = (struct icmp* )&ip_hdr[1];
	
	if(icmp->icmp_type == ICMP_UNREACH) {
		
		struct ip* dst_ip = &icmp->icmp_dun.id_ip.idi_ip;
		
		*src_ip = dst_ip->ip_dst.s_addr;
		validate_gen(ip_hdr->ip_dst.s_addr, dst_ip->ip_dst.s_addr,
					 (uint8_t *) validation);
		
		
		
		struct udphdr* udp = (struct udphdr*)&dst_ip[1];
		
		// validate destination port
		if (!check_dst_port(ntohs(udp->uh_sport), num_ports, validation)) {
			return 0;
		}
		return 1;
	}
	
	
	
	pthread_mutex_lock(&statetable_lock);
	
	struct StateData *stateptr = get_StateData(ip_hdr->ip_src.s_addr, ntohs(zconf.target_port), myStateTable);
	pthread_mutex_unlock(&statetable_lock);
	// we have no entry in our database for this connection -> use normal validation
	if(stateptr != NULL) {
		return 1;
	}
	
	
	return 0;
}



int icmp_path_discovery_process_packet(const u_char *packet,
									   __attribute__((unused)) uint32_t len,
									   fieldset_t*  fs, __attribute__((unused))uint32_t *validation, ringbuffer_t* ring)
{
	
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	
	
	
	uint32_t src_ip = ip_hdr->ip_src.s_addr;
	pthread_mutex_lock(&statetable_lock);
	struct StateData* ptr = get_StateData(src_ip, zconf.target_port, myStateTable);
	if (ptr != NULL) {
		ptr->lastActive = now();
	}
	pthread_mutex_unlock(&statetable_lock);
	if(ip_hdr->ip_p == IPPROTO_ICMP) {
		struct icmp* icmp = (struct icmp* )&ip_hdr[1];
		
		if(icmp->icmp_type == ICMP_UNREACH) {
			
			struct ip* dst_ip = &icmp->icmp_dun.id_ip.idi_ip;
			src_ip = dst_ip->ip_dst.s_addr;
			//log_debug("mtu", "Processing: %s with ICMP CODE: %d", inet_ntoa(dst_ip->ip_dst), icmp->icmp_code);
			
			pthread_mutex_lock(&statetable_lock);
			struct StateData* ptr = get_StateData(src_ip, zconf.target_port, myStateTable);
			if (ptr != NULL) {
				ptr->lastActive = now();
			}
			pthread_mutex_unlock(&statetable_lock);
			
			if(icmp->icmp_code == ICMP_UNREACH_PORT) {
				// we are done, what is the MTU?
				//log_debug("mtu", "Port unreach %s", inet_ntoa(dst_ip->ip_dst));
				if (ptr == NULL) {
					// we recorded nothing on our path so assume local mtu
					fs_modify_string(fs, "saddr", make_ip_str(src_ip), 1);
					fs_add_uint64(fs, "mtu", LOCAL_MTU);
					fs_add_string(fs, "ip_mtu", inet_ntoa(ip_hdr->ip_src), 0);
					fs_add_string(fs, "classification", (char*)"no router inbetween", 0);
					fs_add_uint64(fs, "success", 1);
					return EXIT_SUCCESS;
				}else {
					pthread_mutex_lock(&ptr->state_lock);
					struct path_data* path_data = (struct path_data*)ptr->info;
					uint16_t mtu = LOCAL_MTU;
					struct in_addr ip;
					ip.s_addr = src_ip;
					for (int i = 0; i < path_data->next; i++) {
						if (mtu > path_data->host[i].mtu) {
							mtu = path_data->host[i].mtu;
							ip.s_addr = path_data->host[i].ip.s_addr;
						}
					}
					fs_modify_string(fs, "saddr", make_ip_str(src_ip), 1);
					fs_add_uint64(fs, "mtu", mtu);
					fs_add_string(fs, "ip_mtu", inet_ntoa(ip), 0);
					fs_add_string(fs, "classification", (char*)"router inbetween", 0);
					fs_add_uint64(fs, "success", 1);
					pthread_mutex_unlock(&ptr->state_lock);
					
					pthread_mutex_lock(&statetable_lock);
					remove_StateData(src_ip, zconf.target_port, myStateTable);
					pthread_mutex_unlock(&statetable_lock);
					return EXIT_SUCCESS;
				}
			}
			
			if(icmp->icmp_code == ICMP_UNREACH_NEEDFRAG) {
				//log_debug("mtu", "NEED FRAG: %s", inet_ntoa(dst_ip->ip_dst));
				uint32_t datagram_size = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);
				
				if (datagram_size >= sizeof(icmp->icmp_hun.ih_pmtu) + sizeof(struct ip)) {
					uint16_t mtu = ntohs(icmp->icmp_hun.ih_pmtu.ipm_nextmtu);
					if (ptr == NULL) {
						// add a new state
						pthread_mutex_lock(&statetable_lock);
						ptr = insert_StateData(dst_ip->ip_dst.s_addr, zconf.target_port, myStateTable);
						ptr->lastActive = now();
						pthread_mutex_lock(&ptr->state_lock);
						ptr->ip = src_ip;
						ptr->info = NULL;
						ptr->info = malloc(sizeof(struct path_data));
						memset(ptr->info, 0, sizeof(struct path_data));
						struct path_data* path_data = (struct path_data*)ptr->info;
						path_data->next = 0;
						pthread_mutex_unlock(&ptr->state_lock);
						pthread_mutex_unlock(&statetable_lock);
					}
					pthread_mutex_lock(&ptr->state_lock);
					struct path_data* path_data = (struct path_data*)ptr->info;
					path_data->host[path_data->next].ip.s_addr = ip_hdr->ip_src.s_addr;
					//log_debug("mtu", "REP MTU: %d", mtu);
					path_data->host[path_data->next].mtu = mtu;
					path_data->next++;
					pthread_mutex_unlock(&ptr->state_lock);
					
					
					fs_modify_string(fs, "saddr", make_ip_str(src_ip), 1);
					fs_add_uint64(fs, "mtu", mtu);
					fs_add_string(fs, "ip_mtu", inet_ntoa(ip_hdr->ip_src), 0);
					fs_add_string(fs, "classification", (char*)"not done yet", 0);
					fs_add_uint64(fs, "success", 0);
					
					if (mtu == 0 || mtu > module_icmp_mtu_discovery.ringbuffer_packet_len) {
						return EXIT_FAILURE;
					}
					
					// okay now send a new packet with this smaller mtu
					
					uint8_t* data;
					ringbuffer_lock(ring);
					ringbuffer_reserve(ring, &data, NULL);
					struct ether_header *eth_header = (struct ether_header *)data;
					struct ip *ip_header = (struct ip*)(&eth_header[1]);
					struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
					
					ip_header->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
					ip_header->ip_dst.s_addr = dst_ip->ip_dst.s_addr;
					ip_header->ip_off |= htons(IP_DF);
					ip_header->ip_p = IPPROTO_UDP;
					ip_header->ip_ttl = START_TTL;
					
					unsigned int payload_len = mtu - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct udphdr);
					
					// Update the IP and UDP headers to match the new payload length
					ip_header->ip_len   = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_len);
					udp_header->uh_ulen = ntohs(sizeof(struct udphdr) + payload_len);
					
					
					memset((char*)&udp_header[1], 0, payload_len);
					
					
					// if sum == 0 -> IPv4 will ignore the UDP checksum
					udp_header->uh_sum = 0;
					
					
					alias_unsigned_short *src_addr = (alias_unsigned_short *) &ip_hdr->ip_dst.s_addr;
					alias_unsigned_short *dest_addr = (alias_unsigned_short *) &dst_ip->ip_dst.s_addr;
					
					// calculate udp checksum... which is with only 0 as payload is only the pseudo header
					unsigned long sum = 0;
					sum += src_addr[0];
					sum += src_addr[1];
					sum += dest_addr[0];
					sum += dest_addr[1];
					sum += htons(IPPROTO_UDP);
					sum += udp_header->uh_ulen;
					sum += udp_header->uh_sport;
					sum += udp_header->uh_dport;
					sum += udp_header->uh_ulen;
					//	sum += udp_header->uh_sum;
					sum = (sum >> 16) + (sum & 0xFFFF);
					sum += (sum >> 16);
					
					udp_header->uh_sum = (u_short)~sum;
					
					ip_header->ip_sum = 0;
					ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);
					
					
					ringbuffer_commit(ring, mtu);
					ringbuffer_unlock(ring);
					
					return EXIT_FAILURE;
					
				}
			}
			
		}
	}
	
	return EXIT_FAILURE;
}


void icmp_path_discovery_process_timeout(struct StateData* data) {
	pthread_mutex_lock(&data->state_lock);
	struct path_data* path_data = (struct path_data*)data->info;
	uint16_t mtu = LOCAL_MTU;
	struct in_addr ip;
	
	ip.s_addr = data->ip;
	for (int i = 0; i < path_data->next; i++) {
		if (mtu > path_data->host[i].mtu) {
			mtu = path_data->host[i].mtu;
			ip.s_addr = path_data->host[i].ip.s_addr;
		}
	}
	
	
	//log_debug("mtu", "Processing timeout %s", inet_ntoa(ip));
	
	
	fieldset_t *fs = fs_new_fieldset();

	 // the order is important !!! first the ip fields
	fs_add_string(fs, "saddr", make_ip_str(data->ip), 1);
	fs_add_uint64(fs, "saddr_raw", (uint64_t) data->ip);
	fs_add_string(fs, "daddr", make_ip_str(0), 1);
	fs_add_uint64(fs, "daddr_raw", 0);
	fs_add_uint64(fs, "ipid", 0);
	fs_add_uint64(fs, "ttl", 255);
	
	// now our fields
	fs_add_uint64(fs, "mtu", mtu);
	fs_add_string(fs, "ip_mtu", inet_ntoa(ip), 0);
	fs_add_string(fs, "classification", (char*)"timeout router inbetween", 0);
	fs_add_uint64(fs, "success", 1);
	fs_add_string(fs, "info", (char*)"timedout", 0);
	pthread_mutex_unlock(&data->state_lock);
	
	// the the system fields
	fs_add_system_fields(fs, 3, zsend.complete);
	fieldset_t *o = NULL;
	
	if (!evaluate_expression(zconf.filter.expression, fs)) {
		log_debug("mtu", "Filtered");
		goto cleanup;
	}
	
	o = translate_fieldset(fs, &zconf.fsconf.translation);
	
	

	if (zconf.output_module && zconf.output_module->process_ip) {
		// lock the output to not interleave writing attempts
		pthread_mutex_lock(&recv_mutex);
		
		zconf.output_module->process_ip(o);
		
		pthread_mutex_unlock(&recv_mutex);
	}
cleanup:
	fs_free(fs);
	free(o);

}

static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
	{.name = "mtu", .type="int", .desc = "MTU"},
	{.name = "ip_mtu", .type="string", .desc = "IP responsible for the mtu (e.g. a router)"},
	{.name = "info", .type="string", .desc = "additional infos"}
};

probe_module_t module_icmp_mtu_discovery = {
	.name = "icmp_mtu_discovery",
	.state_aware = 1,
	.ringbuffer_packet_len = 1500,
	.packet_length = 1500,
	.pcap_filter = "icmp",
	.pcap_snaplen = 1500,
	.port_args = 1,
	.global_initialize = &icmp_path_discovery_global_initialize,
	.thread_initialize = &icmp_path_discovery_init_perthread,
	.make_packet = &icmp_path_discovery_make_packet,
	.print_packet = &icmp_path_discovery_print_packet,
	.process_packet_aware = &icmp_path_discovery_process_packet,
	.validate_packet = &icmp_path_discovery_validate_packet,
	.process_timeout = &icmp_path_discovery_process_timeout,
	.close = NULL,
	.helptext = "Probe module that sends a SYN to a specific"
	"port (usually 80). On a syn ack, an http connection gets established."
	"We count the number of packets and bytes sent until the first dup ack"
	"is received. ",
	.fields = fields,
	.numfields = 5};

