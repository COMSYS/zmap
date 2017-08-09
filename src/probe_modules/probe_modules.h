#include "../state.h"
#include "../fieldset.h"
#include "../ringbuffer.h"
#include "state_machine.h"

#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#define OUTPUT_TYPE_STATIC 1
#define OUTPUT_TYPE_DYNAMIC 2

typedef struct probe_response_type {
		const uint8_t is_success;
		const char *name;
} response_type_t;

typedef int (*probe_global_init_cb)(struct state_conf *);
typedef int (*probe_thread_init_cb)(void* packetbuf, macaddr_t* src_mac,
		macaddr_t* gw_mac, port_n_t src_port, void **arg_ptr);

typedef int (*probe_make_packet_cb)(void* packetbuf, size_t *buf_len,
		ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint32_t *validation,
		int probe_num, void *arg);

typedef void (*probe_print_packet_cb)(FILE *, void* packetbuf);
typedef int (*probe_close_cb)(struct state_conf*,
		struct state_send*, struct state_recv*);
typedef int (*probe_validate_packet_cb)(const struct ip *ip_hdr,
		uint32_t len, uint32_t *src_ip, uint32_t *validation);

typedef void (*probe_classify_packet_cb)(const u_char* packetbuf,
		uint32_t len, fieldset_t*, uint32_t *validation);

typedef int (*probe_classify_packet_aware_cb)(const u_char* packetbuf,
uint32_t len, fieldset_t*, uint32_t *validation, ringbuffer_t* ring);


typedef void (*probe_process_timeout_cb)(struct StateData* data);


typedef int (*probe_pcap_filter_func)(char* pcap_filter, size_t max_len);

typedef struct probe_module {
	const char *name;
	size_t packet_length;
	const char *pcap_filter;
	size_t pcap_snaplen;
	probe_pcap_filter_func pcap_filter_func;

	// Should ZMap complain if the user hasn't specified valid
	// source and target port numbers?
	uint8_t port_args;

	probe_global_init_cb global_initialize;
	probe_thread_init_cb thread_initialize;
	probe_make_packet_cb make_packet;
	probe_print_packet_cb print_packet;
	probe_validate_packet_cb validate_packet;
	probe_classify_packet_cb process_packet;
	probe_classify_packet_aware_cb process_packet_aware;
	probe_process_timeout_cb process_timeout;
	probe_close_cb close;
	int state_aware;
	int ringbuffer_packet_len;
    int output_type;
	fielddef_t *fields;
	int numfields;
	const char *helptext;

} probe_module_t;

probe_module_t* get_probe_module_by_name(const char*);

void fs_add_ip_fields(fieldset_t *fs, struct ip *ip);
void fs_add_system_fields(fieldset_t *fs, int is_repeat, int in_cooldown);
void print_probe_modules(void);

extern int ip_fields_len;
extern int sys_fields_len;
extern fielddef_t ip_fields[];
extern fielddef_t sys_fields[];
extern pthread_mutex_t statetable_lock;

#endif // HEADER_PROBE_MODULES_H

