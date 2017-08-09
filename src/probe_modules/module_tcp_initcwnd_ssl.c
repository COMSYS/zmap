// probe module for performing SSL initial window scans

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
#include "tls.h"

#include "initcwnd_common.h"

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#define BUFFERSIZE 16384
#define MAX_ARRAY 100
#define STATE_LOCATION 64
#define MAX_PACKETS 200

FILE* sni_res;
int tcp_initcwnd_ssl_global_initialize(struct state_conf* state)
{
    sni_res = fopen("./sni-res", "r");
    return initcwnd_global_initialize(state);
}

uint16_t make_client_hello(char* payload, uint32_t src_ip)
{
    uint16_t payload_length;
    memset(payload, 0, sizeof(struct tls_record) + sizeof(struct tls_handshake) + sizeof(struct tls_client_hello) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_status_req)) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_ec_point_format) + 1) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_ec_curves) + sizeof(tls_curves)));
    
    struct tls_record* record = (struct tls_record*)payload;
    struct tls_handshake* handshake = (struct tls_handshake*)&record[1];
    struct tls_client_hello* hello = (struct tls_client_hello*)&handshake[1];
    record->content_type = TLS_HANDSHAKE;
    memcpy(record->tls_version, TLS_VERSION_10, sizeof(record->tls_version));
    record->length = htons(sizeof(struct tls_handshake) + sizeof(struct tls_client_hello));
    
    handshake->msg_type = TLS_HANDSHAKE_CLIENTHELLO;
    handshake->handshake_msg_len[2] = sizeof(struct tls_client_hello);
    
    memcpy(hello->tls_version, TLS_VERSION_12, sizeof(hello->tls_version));
    hello->random.gmt_unix_time = htonl(time(NULL));
    hello->session_id_length = 0;
    hello->cipher_suit_length = htons(sizeof(hello->ciphers));
    for(uint16_t i = 0; i < sizeof(hello->ciphers)/sizeof(tls_ciphers[0]); i++) {
        hello->ciphers[i] = tls_ciphers[i];
    }
    hello->compression_method_length = 1;
    hello->compression_method = 0;
    hello->extension_length = 0;
    
    payload_length = sizeof(struct tls_record) + sizeof(struct tls_handshake) + sizeof(struct tls_client_hello);
    
    uint16_t extension_length = 0;
    
    // Request OCSP Stapling
    struct tls_ext* extension = (struct tls_ext*)&hello[1];
    memcpy(extension->type, TLS_EXT_TYPE_STATUS, sizeof(extension->type));
    extension->length = htons(sizeof(struct tls_ext_status_req));
    extension_length += sizeof(struct tls_ext);
    
    struct tls_ext_status_req* status =(struct tls_ext_status_req*)(((char*)&hello[1]) + extension_length);
    status->cert_status_type = TLS_STATUS_TYPE_OCSP;
    status->responder_list_len = htons(0);
    status->req_ext_len = htons(0);
    
    extension_length += sizeof(struct tls_ext_status_req);
    
    // Give EC Formats
    extension = (struct tls_ext*)(((char*)&hello[1]) + extension_length);
    memcpy(extension->type, TLS_EXT_TYPE_EC_POINT_FORMAT, sizeof(extension->type));
    extension->length = htons(sizeof(struct tls_ext_ec_point_format) + 1);
    extension_length += sizeof(struct tls_ext);
    
    struct tls_ext_ec_point_format* ec_formats =(struct tls_ext_ec_point_format*)(((char*)&hello[1]) + extension_length);
    ec_formats->ec_point_format_len = 1;
    
    extension_length += sizeof(struct tls_ext_ec_point_format);
    
    uint8_t* data = (((uint8_t*)&hello[1]) + extension_length);
    *data = TLS_EC_POINT_FORMAT_UNCOMPRESSED;
    //				*(data+1) = TLS_EC_POINT_FORMAT_ASNI_COMPRESSED_PRIME;
    //				*(data+2) = TLS_EC_POINT_FORMAT_ASNI_COMPRESSED_CHAR2;
    
    extension_length += 1;
    
    // Give EC Curves
    extension = (struct tls_ext*)(((char*)&hello[1]) + extension_length);
    memcpy(extension->type, TLS_EXT_TYPE_EC_CURVES, sizeof(extension->type));
    extension->length = htons(sizeof(struct tls_ext_ec_curves) + sizeof(tls_curves));
    extension_length += sizeof(struct tls_ext);
    
    struct tls_ext_ec_curves* ec_curves =(struct tls_ext_ec_curves*)(((char*)&hello[1]) + extension_length);
    ec_curves->len_curves = htons(sizeof(tls_curves));
    
    extension_length += sizeof(struct tls_ext_ec_curves);
    
    data = (((uint8_t*)&hello[1]) + extension_length);
    memcpy(data, tls_curves, sizeof(tls_curves));
    
    extension_length += sizeof(tls_curves);
    
    // set signature algorithms
    extension = (struct tls_ext*)(((char*)&hello[1]) + extension_length);
    memcpy(extension->type, TLS_EXT_TYPE_SIG_ALGOS, sizeof(extension->type));
    extension->length = htons(sizeof(struct tls_ext_sig_algos) + sizeof(tls_sig_algos));
    extension_length += sizeof(struct tls_ext);
    struct tls_ext_sig_algos* sig_algos = (struct tls_ext_sig_algos*)(((char*)&hello[1]) + extension_length);
    sig_algos->len_algos = htons(sizeof(tls_sig_algos));
    sig_algos->len_all = htons(sizeof(tls_sig_algos) + sizeof(sig_algos->len_algos)); 

    extension_length += sizeof(struct tls_ext_sig_algos);

    data = (((uint8_t*)&hello[1]) + extension_length);
    memcpy(data, tls_sig_algos, sizeof(tls_sig_algos));

    extension_length += sizeof(tls_sig_algos);

    // check if we need a SNI extension
    // this should be improved (performance, format) once the full
    // list of IP-to-SNI resolutions is available
    
    if (sni_res != NULL) {
        rewind(sni_res);
        char ip[15];
        char url[40];
        struct in_addr addr;
        int found = 0;
        while (fscanf(sni_res, "%s %s", ip, url) != EOF) {
            if (inet_aton(ip, &addr) && addr.s_addr == src_ip) {
                log_info("iwssl", "resolving ip %s with url %s", ip, url);
                found = 1;
                break;
            }
        }
        if (found) {
            extension = (struct tls_ext*)(((char*)&hello[1]) + extension_length);
            memcpy(extension->type, TLS_EXT_TYPE_SERVER_NAME, sizeof(extension->type));
            extension->length = htons(sizeof(struct tls_ext_sni) + strlen(url));
            extension_length += sizeof(struct tls_ext);
            struct tls_ext_sni* sni_ext = (struct tls_ext_sni*)(((char*)&hello[1]) + extension_length);
            sni_ext->ext_size = htons(sizeof(struct tls_ext_sni) + strlen(url) - sizeof(uint16_t));
            sni_ext->name_type = 0;
            sni_ext->name_length = htons(strlen(url));

            extension_length += sizeof(struct tls_ext_sni);
            data = (((uint8_t*)&hello[1]) + extension_length);
            strcpy((char*)data, url);
            extension_length += strlen(url);
        }
    }
    
    // set all lengthfields to include extensions
    hello->extension_length = htons(extension_length);
    record->length = htons(sizeof(struct tls_handshake) + sizeof(struct tls_client_hello) + extension_length);
    // urgs lets hope we remain below 3 bytes...
    *((uint16_t*)&handshake->handshake_msg_len[1]) = htons(sizeof(struct tls_client_hello) + extension_length);
    
    payload_length += extension_length;
    
    log_debug("initcwnd", "tls len calc is %u summed is %u", sizeof(struct tls_record) + sizeof(struct tls_handshake) + sizeof(struct tls_client_hello) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_status_req)) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_ec_point_format) + 1) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_ec_curves) + sizeof(tls_curves)) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_sig_algos) + sizeof(tls_sig_algos)), payload_length);                                      

	return payload_length;
}

static int pseudo_redirect(__attribute__((unused)) const u_char* packet, __attribute__((unused)) uint32_t src_ip, __attribute__((unused)) uint32_t dport, __attribute__((unused)) ringbuffer_t* ring)
{
    return EXIT_FAILURE;
}

static int pseudo_synack_redirected(__attribute__((unused)) struct ip* ip, __attribute__((unused)) struct tcphdr* tcp, __attribute__((unused)) struct StateData* ptr, __attribute__((unused)) ringbuffer_t* ring)
{
    return EXIT_FAILURE;
}

int tcp_initcwnd_ssl_process_packet(const u_char *packet,
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
        return initcwnd_process_RST(src_ip, tcp, ptr, fs, packet, ring, pseudo_redirect);
	}
	// NO RST --> connection working
	else {
		
		if(ptr != NULL) { // connection is known
            return initcwnd_process_known_connection(packet, src_ip, ptr, ip_hdr, tcp, ring, fs, pseudo_redirect, pseudo_synack_redirected);
        }else {
			if(tcp->th_flags & TH_SYN && tcp->th_flags & TH_ACK) { // SYN ACK
                int probe_num_plus1 = check_dst_port(ntohs(tcp->th_dport), num_ports, validation);
                if (!probe_num_plus1) {
                    log_error("iwssl", "invalid probe_num validation in SYNACK");
                    return initcwnd_process_unknown_packet(packet, tcp, ring, fs);
                }

                initcwnd_process_SYNACK(tcp, ip_hdr, ring, packet, probe_num_plus1 - 1, make_client_hello);
                return EXIT_FAILURE;
            }else { // unknown answer
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

probe_module_t module_tcp_initcwnd_ssl = {
	.name = "tcp_initcwnd_ssl",
	.state_aware = 1,
	.ringbuffer_packet_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct tls_record) + sizeof(struct tls_handshake) + sizeof(struct tls_client_hello) + sizeof(struct tls_record) + sizeof(struct tls_handshake) + sizeof(struct tls_client_hello) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_status_req)) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_ec_point_format) + 1) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_ec_curves) + sizeof(tls_curves)) + (sizeof(struct tls_ext) + sizeof(struct tls_ext_sig_algos) + sizeof(tls_sig_algos)),
    .packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 4,
    //.packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 8, //SACK
	.pcap_filter = "tcp",
    .pcap_filter_func = &initcwnd_pcap_filter,
	.pcap_snaplen = TCP_SNAPLEN,
	.port_args = 1,
	.global_initialize = &tcp_initcwnd_ssl_global_initialize,
    .thread_initialize = &initcwnd_init_perthread,
    .make_packet = &initcwnd_make_packet,
    .print_packet = &initcwnd_print_packet,
	.process_packet_aware = &tcp_initcwnd_ssl_process_packet,
    .validate_packet = &initcwnd_validate_packet,
    .process_timeout = &initcwnd_process_timeout,
	.close = NULL,
	.helptext = "Probe module that sends a SYN to a specific"
	"port (usually 80). On a syn ack, an http connection gets established."
	"We count the number of packets and bytes sent until the first dup ack"
	"is received. ",
	.fields = fields,
	.numfields = sizeof(fields) / sizeof(fields[0]) };

//sudo ./src/zmap -p443 -T1 -R1 -r 150000 -M tcp_initcwnd_ssl -f "saddr, classification, success, packets, payload, completed, assumption, seq_len, rep_mss, info"  -i eth1 -G $(../get_gw_hw.sh) -v3 -O json -o /mnt/disk2/initcwnd_ssl/initcwnd_MSS64_tls_2016_05_11.json -b /etc/scan_blacklist.conf -d
