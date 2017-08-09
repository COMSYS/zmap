#pragma once

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

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define BUFFERSIZE 16384
#define MAX_ARRAY 100
#define TCP_SNAPLEN 1000
#define MAX_PACKETS 200

#define STATE_REDIRECT 128
#define STATE_LOCATION 64
#define STATE_LOCATION_LONG 32

#define TH_ECE 0x40
#define TH_CWR 0x80

typedef uint16_t (*packet_builder)(char*, uint32_t);
typedef int (*redirect_function)(const u_char*, uint32_t, uint32_t, ringbuffer_t*);
typedef int (*redirect_synack_processor)(struct ip*, struct tcphdr*, struct StateData*, ringbuffer_t*);

extern uint32_t num_ports;
extern skipList* myList;
extern uint8_t mss_retries;
extern uint16_t* mss_buf;
extern pthread_mutex_t recv_mutex;

struct initcwnd_Data {
    char buffer[BUFFERSIZE];         // Buffer to hold payload
    uint32_t bytes;                  // # of bytes (payload)
    uint32_t packets;                // # of packets
    uint32_t seq;                    // highest seen seq numbers
    uint32_t seq_start;              // seq number for the start of payload
    uint32_t len_high_seq_pack;      // length of the packet with the highest sequence number
    uint32_t buf_offset;             // current position in buffer
    uint32_t seq_array[MAX_ARRAY];   // save all seq numbers in case they didn't arrive in order
    uint32_t seq_iterator;           // # of saved seq numbers
    uint8_t requests;                // # of requests sent
};

int initcwnd_global_initialize(struct state_conf* state);

int initcwnd_pcap_filter(char* out_filter, size_t max_len);

int initcwnd_init_perthread(void* buf, macaddr_t* src, macaddr_t* gw, port_h_t dst_port, void** arg_ptr);

void initcwnd_print_packet(FILE* fp, void* packet);

int initcwnd_make_packet(void* buf, UNUSED size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint32_t* validation, int probe_num, void* arg);

int initcwnd_validate_packet(const struct ip* ip_hdr, uint32_t len, uint32_t* src_ip, uint32_t* validation);

void initcwnd_copy(const u_char* packet, struct initcwnd_Data* data_ptr);

void initcwnd_create_stateinfo(uint32_t src_ip, struct tcphdr* tcp, uint16_t offset, int probe_num);

void initcwnd_process_SYNACK(struct tcphdr* tcp, struct ip* ip_hdr, ringbuffer_t* ring, const u_char* packet, int probe_num, packet_builder builder);

int initcwnd_process_RST(uint32_t src_ip, struct tcphdr* tcp, struct StateData* ptr, fieldset_t* fs, const u_char* packet, ringbuffer_t* ring, redirect_function redirect);

void initcwnd_process_first_segment(const u_char* packet, struct StateData* ptr, struct tcphdr* tcp, uint32_t payload);

int initcwnd_process_unknown_packet(const u_char* packet, struct tcphdr* tcp, ringbuffer_t* ring, fieldset_t* fs);

int initcwnd_process_known_connection(const u_char* packet, uint32_t src_ip, struct StateData* ptr, struct ip* ip_hdr, struct tcphdr* tcp, ringbuffer_t* ring, fieldset_t* fs, redirect_function redirect, redirect_synack_processor synack_redirected);

void initcwnd_process_timeout(struct StateData* data);
