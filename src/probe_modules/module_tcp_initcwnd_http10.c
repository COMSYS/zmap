/**
 *
 * Send request, get data, other side will FIN if they sent everything out, if we do not receive a FIN before the DUP ACK we are good.
 *
 */

// probe module for performing HTTP initial window scans
#define _GNU_SOURCE 1

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

#include "state_machine.h"
#include "tcp_connection.h"
#include "ipdata.h"

#include "initcwnd_common.h"

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#define BUFFERSIZE 16384
#define MAX_ARRAY 100
#define STATE_REDIRECT 128
#define STATE_LOCATION 64
#define STATE_LOCATION_LONG 32
#define MAX_PACKETS 200
#define TCP_SNAPLEN 1000

int tcp_http10_initcwnd_redirect(const u_char* packet, uint32_t src_ip, uint32_t dport, ringbuffer_t* ring) {
	// State machine entry
//	log_debug("iw", "Should redirect");
	pthread_mutex_lock(&statetable_lock);
	struct StateData* struct_ptr = get_StateData(src_ip, dport, myStateTable);
    //printf("%d, %d, %p\n", src_ip, dport, (void*)struct_ptr);
	if (struct_ptr != NULL) {
		struct_ptr->lastActive = now();
	}
	pthread_mutex_unlock(&statetable_lock);

	if(struct_ptr == NULL) {
//		log_debug("iw", "No state");
		return EXIT_FAILURE;
	}

    int probe_num = struct_ptr->probe_num;

	// Buffer entry
	if((struct_ptr->state & (STATE_LOCATION|STATE_LOCATION_LONG)) == 0) {
		
		struct initcwnd_Data* data_ptr = (struct initcwnd_Data*)struct_ptr->info;
		if (data_ptr != NULL) {
			
			pthread_mutex_lock(&struct_ptr->state_lock);
			// This should not be necessary
			data_ptr->buffer[BUFFERSIZE-1] = '\0';
			pthread_mutex_unlock(&struct_ptr->state_lock);
			// Search for Location header
			char* string_find = strstr(data_ptr->buffer, "Location: ");
			if(string_find != NULL && ((struct_ptr->state & STATE_LOCATION) == 0)) {
				//	log_debug("iw", "Trying a redirect");
				char* cur = string_find;
				char* end = NULL;
				// Search for \r\n
				//log_debug("initcwnd","Found location");
				while(end == NULL && cur < data_ptr->buffer + data_ptr->buf_offset && cur < data_ptr->buffer + BUFFERSIZE) {
					if((*cur == '\r' && *(cur+1) == '\n') || *cur == '\n') {
						end = cur;
					}
					cur++;
				}
				if(end != NULL && (end-string_find) != 0) {
					// Check if the server wants https
					char* string_find_https = strcasestr(string_find, "https://");
					char* string_find_http = strcasestr(string_find, "http://");
					
					int size = end-string_find;
					char* location = malloc(size+17);
					// malloc failed
					if(location == NULL) {
						log_debug("iw", "Malloc error");
						return EXIT_FAILURE;
					}
					memset(location, 0, size+17);
					// Server tries to redirect to https instead of http
					if (string_find_https > string_find && string_find_https < end) {
						// https:// -> 8 characters
						// Location:  -> 10 characters
						size = end-string_find-10-8+1;
						memcpy(location, string_find+10+8,size-1);
					}
					else {
						if(string_find_http > string_find &&  string_find_http < end) {
							// there is a http in the string
							size = end-string_find-10-7+1;
							if(size<=0 || size>150) {
								free(location);
								//	log_debug("iw", "http string to long");
								return EXIT_FAILURE;
							}
							memcpy(location, string_find+10+7,size-1);
						}
						else {
							// there is no http or https in the string... this is still valid...
							uint8_t src_ips[4];
							src_ips[3] = (uint8_t)(src_ip >> 24);
							src_ips[2] = (uint8_t)(src_ip >> 16);
							src_ips[1] = (uint8_t)(src_ip >> 8);
							src_ips[0] = (uint8_t)(src_ip >> 0);
							int hostlen = snprintf(location, size, "%i.%i.%i.%i/", src_ips[0], src_ips[1], src_ips[2], src_ips[3]);
							if (strstr(string_find+10, "/") == string_find+10) { // first character is a /
								size = end-string_find-11+1;
								memcpy(location+hostlen, string_find+11,size-1);
								size += hostlen;
							}else {
								size = end-string_find-10+1;
								memcpy(location+hostlen, string_find+10,size-1);
								size += hostlen;
							}
						}
					}
					if(size < 2) {
						free(location);
						log_debug("iw", "failed to to size error");
						return EXIT_FAILURE;
					}
					assert(size > 1);
					location[size-1] = '\0';
					if(location[size-2] == '/') {
						location[size-2] = '\0';
					}
					
					// try to see if there is a cookie along with the response, often required on redirect
#define SET_COOKIE_LEN (12)
					//Cookie:
#define COOKIE_LEN (8)
					char* string_find_setcookie = strcasestr(data_ptr->buffer, "Set-Cookie: ");
					
					if (string_find_setcookie > string_find) {
						cur = string_find_setcookie;
						end = NULL;
						while(end == NULL && cur < data_ptr->buffer + data_ptr->buf_offset && cur < data_ptr->buffer + BUFFERSIZE) {
							if((*cur == '\r' && *(cur+1) == '\n') || *cur == '\n') {
								end = cur;
							}
							cur++;
						}
						if(string_find_setcookie < end) {
							size = end-string_find_setcookie-SET_COOKIE_LEN; // this is the size including the initial Set-Cookie:
							// oh boy this is gonna be ugly
							int loclen = strlen(location);
							location = realloc(location, loclen+size+2);
							//
							location[loclen] = '|'; // we use this to delimit url from cookie
							memcpy(location+loclen+1, string_find_setcookie+SET_COOKIE_LEN, size);
							location[loclen+1+size] = '\0';
						}
					}
					// Reset the current connection
					uint8_t* data = NULL;
					uint32_t len;
					
					ringbuffer_lock(ring);
					
					ringbuffer_reserve(ring, &data, &len);
					len = tcp_buildRst(packet, data, len);
					ringbuffer_commit(ring, len);
					
					ringbuffer_unlock(ring);
					
					uint32_t new_seqn = struct_ptr->sqn+1;
                    uint16_t mss = mss_buf[struct_ptr->probe_num % mss_retries];
					
					pthread_mutex_lock(&statetable_lock);
					remove_StateData(src_ip, dport, myStateTable);
					pthread_mutex_unlock(&statetable_lock);
					
					// create new connection
					
					u_char* buf = NULL;
					ringbuffer_lock(ring);
					ringbuffer_reserve(ring, &buf, &len);
					tcp_buildAck(packet, buf,  len);
					
					struct ip *ip_hdr;
					struct tcphdr *tcp;
					ip_hdr = (struct ip *)&buf[sizeof(struct ether_header)];
					ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + 4);
					
					tcp = (struct tcphdr*)((char *)ip_hdr + 4*ip_hdr->ip_hl);
					tcp->th_seq = htonl(new_seqn);  // some sqn
					tcp->th_flags = TH_SYN;
					tcp->th_ack = 0;
					
					tcp->th_sport = htons(dport+1);
					tcp->th_dport = htons(zconf.target_port);
					
					tcp->th_off = 6; // 5+1 = 4 bytes more for options
					unsigned char* options = (unsigned char*)(&tcp[1]);
					options[0] = 2;
					options[1] = 4;
					*(uint16_t*)&options[2] = htons(mss);
					
					
					tcp->th_sum = 0;
					
					tcp->th_sum = tcp_checksum(sizeof(struct tcphdr)+4, // +4 bytes for options
											   ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr, tcp);
					
					ip_hdr->ip_sum = 0;
					ip_hdr->ip_sum = zmap_ip_checksum((unsigned short *) ip_hdr);
					
					pthread_mutex_lock(&statetable_lock);
					struct StateData* myptr = insert_StateData(src_ip, ntohs(tcp->th_sport), myStateTable);
					pthread_mutex_unlock(&statetable_lock);
					
					ringbuffer_commit(ring, sizeof(struct ether_header)+sizeof(struct ip) + sizeof(struct tcphdr) + 4);
					
					ringbuffer_unlock(ring);
					pthread_mutex_lock(&myptr->state_lock);
					
					if(myptr != NULL) {
                        //printf("Chaing to STATE_LOCATION FOR %p\n", (void*)myptr);
						myptr->state |= STATE_LOCATION;
						myptr->info = location;
                        myptr->probe_num = probe_num;
					}
					else {
						log_debug("initcwnd","Could not create state information, this should never habben");
						free(location);
					}
					pthread_mutex_unlock(&myptr->state_lock);
					//log_debug("initcwnd", location);
					return EXIT_SUCCESS;
				}
			}
		}else {
			//	log_debug("iw", "State has no data");
		}
    }else {
        //printf("State was already redirected\n");
    }
	// be stupid and try a real long request... somethimes NOT FOUND /DASDASD will be returned
	// Reset the current connection
	//	string_find = strstr(data_ptr->buffer, "Server: AkamaiGHost");
	
	if((struct_ptr->state & (STATE_LOCATION_LONG)) == 0) {
        // printf("In location long %d\n", struct_ptr->state);
		uint8_t* data = NULL;
		uint32_t len;
		ringbuffer_lock(ring);
		
		len = ringbuffer_reserve(ring, &data, NULL);
		if (len == 0) {
			log_error("initcwnd", "No ringbuffer space left");
		}
		//log_debug("initcwnd", "SENDING A RST TO %s", inet_ntoa(*(struct in_addr*)&src_ip));
		len = tcp_buildRst(packet, data, len);
		ringbuffer_commit(ring, len);
		
		ringbuffer_unlock(ring);
		
		
		
		
		
		uint32_t new_seqn = struct_ptr->sqn+1;
		uint16_t mss = mss_buf[struct_ptr->probe_num % mss_retries];
        
		// remove from statemachine
		pthread_mutex_lock(&statetable_lock);
		remove_StateData(src_ip, dport, myStateTable);
		pthread_mutex_unlock(&statetable_lock);
		
		//log_debug("iw", "Trying real long url request");
		// create new connection
		u_char* buf = NULL;
		ringbuffer_lock(ring);
        if(ringbuffer_reserve(ring, &buf, &len) == 0) {
            log_error("initcwnd", "No ringbuffer space left");
        }
		
		tcp_buildAck(packet, buf, len);
		
		
		struct ip *ip_hdr;
		struct tcphdr *tcp;
		ip_hdr = (struct ip *)&buf[sizeof(struct ether_header)];
		ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + 4);
		
		tcp = (struct tcphdr*)((char *)ip_hdr + 4*ip_hdr->ip_hl);
		tcp->th_seq = htonl(new_seqn);  // some sqn
		tcp->th_flags = TH_SYN;
		tcp->th_ack = 0;
		tcp->th_sport = htons(dport+1);
		tcp->th_dport = htons(zconf.target_port);
        
		
		tcp->th_off = 6; // 5+1 = 4 bytes more for options
		unsigned char* options = (unsigned char*)(&tcp[1]);
		options[0] = 2;
		options[1] = 4;
		*(uint16_t*)&options[2] = htons(mss);
		
		
		tcp->th_sum = 0;
		
		tcp->th_sum = tcp_checksum(sizeof(struct tcphdr)+4, // +4 bytes for options
								   ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr, tcp);
		
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = zmap_ip_checksum((unsigned short *) ip_hdr);
		
		pthread_mutex_lock(&statetable_lock);
		struct StateData* myptr = insert_StateData(src_ip, ntohs(tcp->th_sport), myStateTable);
		pthread_mutex_unlock(&statetable_lock);
		
		ringbuffer_commit(ring, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 4);
		ringbuffer_unlock(ring);
		
		if(myptr != NULL) {
			pthread_mutex_lock(&myptr->state_lock);
            
			myptr->state |= STATE_LOCATION_LONG;
            //printf("Should not get intfo state long again with %p, state is %d\n", (void*)myptr, myptr->state);
            myptr->probe_num = probe_num;
			if(myptr->info != NULL) {
				free(myptr->info);
				myptr->info = NULL;
			}
			char* url= NULL;
			myptr->info = malloc(1000+20);
			url = (char*)"YesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScanningForResearchPurposePleaseHaveALookAtTheUserAgentTHXYesThisIsAReallyLongRequestURLbutWeAreDoingItOnPurposeWeAreScann\0";
			
			uint8_t src_ips[4];
			src_ips[3] = (uint8_t)(src_ip >> 24);
			src_ips[2] = (uint8_t)(src_ip >> 16);
			src_ips[1] = (uint8_t)(src_ip >> 8);
			src_ips[0] = (uint8_t)(src_ip >> 0);
			snprintf(myptr->info, 1000+20, "%i.%i.%i.%i/%s", src_ips[0], src_ips[1], src_ips[2], src_ips[3], url);
			pthread_mutex_unlock(&myptr->state_lock);
		}
		else {
			log_debug("initcwnd","Could not create state information, this should never habben");
		}
		//log_debug("initcwnd", location);
		return EXIT_SUCCESS;
    }else {
        //printf("Was already in state location long\n");
    }
	return EXIT_FAILURE;
}

uint16_t make_http_get(char* payload, uint32_t src_ip)
{
    // try to get info from skiplist about host
    char* host = search_InputTable(myList,ntohl(src_ip));

    uint8_t src_ips[4];
    src_ips[3] = (uint8_t)(src_ip >> 24);
    src_ips[2] = (uint8_t)(src_ip >> 16);
    src_ips[1] = (uint8_t)(src_ip >> 8);
    src_ips[0] = (uint8_t)(src_ip >> 0);

	uint16_t payload_length;

    if(host==NULL) {
        payload_length = sprintf(payload,"GET / HTTP/1.1\r\nHost: %i.%i.%i.%i\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 Scanning for research (researchscan.comsys.rwth-aachen.de)\r\n\r\n", src_ips[0],src_ips[1],src_ips[2],src_ips[3]);
    }
    else {
        //log_debug("initcwnd","Host ip found: %s",host);
        payload_length = sprintf(payload,"GET / HTTP/1.1\r\nHost:%s\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 Scanning for research (researchscan.comsys.rwth-aachen.de)\r\n\r\n", host);
    }

	return payload_length;
}

int tcp_synack_redirected(struct ip* ip_hdr, struct tcphdr* tcp, struct StateData* ptr, ringbuffer_t* ring)
{
    // Build answer
    // length of the answer:


 // why ack? this is done on the GET anyways...
 // because a lot of servers hate the data + ack thing
    uint8_t* data = NULL;
    unsigned int len;
    ringbuffer_lock(ring);
    
    if((len = ringbuffer_reserve(ring, &data, NULL)) == 0) {
        log_error("iw", "out of ringbuffer");
    }
    len = tcp_buildAck(((uint8_t*)ip_hdr)-sizeof(struct ether_header), data, len);
    ringbuffer_commit(ring, len);
    
    ringbuffer_unlock(ring);


    // Build answer
    int locationlen = strlen((char*)ptr->info);
    // something is wrong with the url
    if(locationlen > 3000 || locationlen <= 0) {
        log_error("IW", "LOCATION LENGTH EXEEDS");
       // return EXIT_FAILURE;
    }
    char* payload = malloc(500+locationlen);
    memset(payload, 0, 500+locationlen);

    // split host and file
    // search at most up to the | to find the URL part
    char* cookiepos = strcasestr(ptr->info, "|");
    if (cookiepos != NULL) {
        *cookiepos = '\0';
        cookiepos += 1;
    }
    char* slash_pos = strstr(ptr->info, "/");
    unsigned int payload_length=0;
    if(slash_pos != NULL) {
        *slash_pos = '\0';
        //log_debug("initcwnd", "Host %s", (char*)ptr->info);
        //log_debug("initcwnd", "/%s", slash_pos+1);
        if (cookiepos) {
            payload_length = snprintf(payload, 500+locationlen ,"GET /%s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 Scanning for research (researchscan.comsys.rwth-aachen.de)\r\n\r\n", slash_pos+1,(char*)ptr->info, cookiepos);
        }else {
            payload_length = snprintf(payload, 500+locationlen,"GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 Scanning for research (researchscan.comsys.rwth-aachen.de)\r\n\r\n", slash_pos+1,(char*)ptr->info);
        }
    }
    else {
        if (cookiepos) {
            payload_length = snprintf(payload,500+locationlen, "GET / HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 Scanning for research (researchscan.comsys.rwth-aachen.de)\r\n\r\n",  (char*)ptr->info, cookiepos);
        }else {
            payload_length = snprintf(payload, 500+locationlen, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36 Scanning for research (researchscan.comsys.rwth-aachen.de)\r\n\r\n",  (char*)ptr->info);
        }
    }
    

    struct ip *ip_hdrs2;
    struct tcphdr *tcps2;
    
    u_char* buf2 = NULL;
    
    ringbuffer_lock(ring);
    unsigned int available = ringbuffer_reserve(ring, &buf2, NULL);
    if (available == 0) {
        log_error("iw", "out of ringbuffer");
    }

    ip_hdrs2 = (struct ip *)&buf2[sizeof(struct ether_header)];
    available -= sizeof(struct ether_header);
    tcps2 = (struct tcphdr*)((char *)ip_hdrs2 + 4*ip_hdrs2->ip_hl);
    
    
    available -= 4*ip_hdrs2->ip_hl + sizeof(struct tcphdr);
    
    tcps2->th_seq = htonl(ntohl(tcp->th_ack));
    tcps2->th_ack = htonl(ntohl(tcp->th_seq)+1);
    
    int offset = payload_length > available ? available : payload_length;
    
    ip_hdrs2->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + offset);
    tcps2->th_off = 5;
    tcps2->th_flags = TH_ACK | TH_PUSH;
    ip_hdrs2->ip_dst = ip_hdr->ip_src;
    ip_hdrs2->ip_src = ip_hdr->ip_dst;
    tcps2->th_sport = tcp->th_dport;
    tcps2->th_dport = tcp->th_sport;
    tcps2->th_win = htons(65535);

    if (payload_length > available) {
        log_error("TOO BIG", "TADAAA");
    }
    memcpy((char *)tcps2 + tcps2->th_off*4, payload, offset);
    free(payload);

    tcps2->th_sum = 0;
    tcps2->th_sum = tcp_checksum(sizeof(struct tcphdr)+offset,
            ip_hdrs2->ip_src.s_addr, ip_hdrs2->ip_dst.s_addr, tcps2);

    ip_hdrs2->ip_sum = 0;
    ip_hdrs2->ip_sum = zmap_ip_checksum((unsigned short *) ip_hdrs2);
    
    ringbuffer_commit(ring, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + offset);
    ringbuffer_unlock(ring);

    pthread_mutex_lock(&ptr->state_lock);
    free(ptr->info);
    ptr->info = NULL;
    ptr->state |= STATE_REDIRECT;
    ptr->sqn = ntohl(tcp->th_ack)+offset;
    ptr->ssqn = ntohl(tcp->th_seq)+1;

    pthread_mutex_unlock(&ptr->state_lock);

    return EXIT_FAILURE;
}

int tcp_http10_initcwnd_process_packet(const u_char *packet,
										   __attribute__((unused)) uint32_t len,
										   fieldset_t*  fs, uint32_t *validation, ringbuffer_t* ring)
{

	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
					+ 4*ip_hdr->ip_hl);
    uint32_t src_ip = ip_hdr->ip_src.s_addr;
	pthread_mutex_lock(&statetable_lock);
	struct StateData* ptr = get_StateData(src_ip, ntohs(tcp->th_dport), myStateTable);
	if (ptr != NULL) {
			ptr->lastActive = now();
	}
	pthread_mutex_unlock(&statetable_lock);
	if (tcp->th_flags & TH_RST) { // RST packet
        return initcwnd_process_RST(src_ip, tcp, ptr, fs, packet, ring, tcp_http10_initcwnd_redirect);
    }
    // NO RST --> connection working
    else {
        if(ptr != NULL) { // connection is known
            return initcwnd_process_known_connection(packet, src_ip, ptr, ip_hdr, tcp, ring, fs, tcp_http10_initcwnd_redirect, tcp_synack_redirected);
        }
        else {
            if(tcp->th_flags & TH_SYN && tcp->th_flags & TH_ACK) {
                int probe_num_plus1 = check_dst_port(ntohs(tcp->th_dport), num_ports, validation);
                if (!probe_num_plus1) {
                    //log_error("iwhttp", "invalid probe_num validation in SYNACK");
                    return initcwnd_process_unknown_packet(packet, tcp, ring, fs);
                }

                initcwnd_process_SYNACK(tcp, ip_hdr, ring, packet, probe_num_plus1 - 1, make_http_get);
                return EXIT_FAILURE;
            }
            else { //unknown answer
                return initcwnd_process_unknown_packet(packet, tcp, ring, fs);
            }
        }
    }
    return EXIT_FAILURE;
}

static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet classification"},
    {.name = "success", .type="int", .desc = "is response considered success"},
    {.name = "packets", .type="int", .desc = "Number of packets with payload"},
    {.name = "payload", .type="int", .desc = "Payload in bytes"},
    {.name = "completed", .type="string", .desc = "Was everything sent?"},
    {.name = "assumption", .type="int", .desc = "Assumed initcwnd"},
	{.name = "seq_len", .type="int", .desc = "calculated length from seq numbers"},
	{.name = "rep_mss", .type="int", .desc = "reported mss"},
    {.name = "req_mss", .type="int", .desc = "requested mss"},
    {.name = "probe_num", .type="int", .desc = "index of probe for this host and mss"},
	{.name = "info", .type="string", .desc = "additional infos"}
};

probe_module_t module_tcp_http10_initcwnd = {
    .name = "tcp_initcwnd_http",
	.state_aware = 1,
	.ringbuffer_packet_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 1300,
	.packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 4,
	.pcap_filter = "tcp port 80",
    .pcap_filter_func = &initcwnd_pcap_filter,
	.pcap_snaplen = TCP_SNAPLEN,
	.port_args = 1,
    .global_initialize = &initcwnd_global_initialize,
    .thread_initialize = &initcwnd_init_perthread,
    .make_packet = &initcwnd_make_packet,
    .print_packet = &initcwnd_print_packet,
    .process_packet_aware = &tcp_http10_initcwnd_process_packet,
    .validate_packet = &initcwnd_validate_packet,
    .process_timeout = &initcwnd_process_timeout,
	.close = NULL,
    .helptext = "Probe module that sends a SYN to a specific"
        "port (usually 80). On a syn ack, an http connection gets established."
        "We count the number of packets and bytes sent until the first dup ack"
        "is received. ",
	.fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0]) };

