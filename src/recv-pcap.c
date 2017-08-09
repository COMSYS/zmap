/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */


#include "recv.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <pcap.h>
#include <pcap/pcap.h>

#include "recv-internal.h"
#include "state.h"
#include "ringbuffer.h"

#include "probe_modules/probe_modules.h"

#define PCAP_PROMISC 1
#define PCAP_TIMEOUT 1



static pcap_t *pc = NULL;
static unsigned long long packet_counter;

void packet_cb(u_char *user,
		const struct pcap_pkthdr *p, const u_char *bytes)
{
	packet_counter++;
	if (!p) {
		return;
	}
	
	ringbuffer_t* ring = (ringbuffer_t*)user;
	if (zrecv.success_unique >= zconf.max_results) {
		// Libpcap can process multiple packets per pcap_dispatch;
		// we need to throw out results once we've
		// gotten our --max-results worth.
		return;
	}
	// length of entire packet captured by libpcap
	uint32_t buflen = (uint32_t) p->caplen;
	handle_packet(buflen, bytes, ring);
}

#define BPFLEN 1024

void recv_init()
{
	char bpftmp[BPFLEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	//pc = pcap_open_live(zconf.iface, zconf.probe_module->pcap_snaplen, PCAP_PROMISC, PCAP_TIMEOUT, errbuf);
	pc = pcap_create(zconf.iface, errbuf);
	pcap_set_snaplen(pc, zconf.probe_module->pcap_snaplen);
	pcap_set_promisc(pc, PCAP_PROMISC);
	pcap_set_timeout(pc, PCAP_TIMEOUT);
	pcap_set_buffer_size(pc, PCAP_BUFFER_SIZE); // set live buffer to 20MB (default:2MB)
	if(pcap_activate(pc) != 0) {
		log_fatal("recv", "could not activate capture: %s",	pcap_geterr(pc));

	}
	if (pc == NULL) {
		log_fatal("recv", "could not open device %s: %s",
						zconf.iface, errbuf);
	}
	struct bpf_program bpf;

	snprintf(bpftmp, sizeof(bpftmp)-1, "not ether src %02x:%02x:%02x:%02x:%02x:%02x",
		zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
		zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5]);
	assert(strlen(zconf.probe_module->pcap_filter) + 10 < (BPFLEN - strlen(bpftmp)));
	if (zconf.probe_module->pcap_filter_func) {
		strcat(bpftmp, " and (");
		size_t cur_len = strlen(bpftmp);
		if (zconf.probe_module->pcap_filter_func(((char*)bpftmp)+cur_len, BPFLEN-cur_len) != 0 && zconf.probe_module->pcap_filter) {
			strcat(bpftmp, zconf.probe_module->pcap_filter);
		}
		strcat(bpftmp, ")");
	}else if (zconf.probe_module->pcap_filter) {
		strcat(bpftmp, " and (");
		strcat(bpftmp, zconf.probe_module->pcap_filter);
		strcat(bpftmp, ")");
	}
	
	log_debug("pcap", "Using filter: %s\n", bpftmp);
	
	if (pcap_compile(pc, &bpf, bpftmp, 1, 0) < 0) {
		log_fatal("recv", "couldn't compile filter: %s", pcap_geterr(pc));
	}
	if (pcap_setfilter(pc, &bpf) < 0) {
		log_fatal("recv", "couldn't install filter");
	}
	// set pcap_dispatch to not hang if it never receives any packets
	// this could occur if you ever scan a small number of hosts as
	// documented in issue #74.
	if (pcap_setnonblock (pc, 1, errbuf) == -1) {
		log_fatal("recv", "pcap_setnonblock error:%s", errbuf);
	}
}

void recv_packets(ringbuffer_t* ring)
{
	int ret = pcap_dispatch(pc, -1, packet_cb, (u_char*)ring);
	if (ret == -1) {
		log_fatal("recv", "pcap_dispatch error");
	} else if (ret == 0) {
		usleep(1000);
	}
}

void recv_cleanup_shared()
{
	pcap_close(pc);
	pc = NULL;
}

int recv_update_stats(void)
{
	if (!pc) {
		return EXIT_FAILURE;
	}
	struct pcap_stat pcst;
	if (pcap_stats(pc, &pcst)) {
		log_error("recv", "unable to retrieve pcap statistics: %s",
				pcap_geterr(pc));
		return EXIT_FAILURE;
	} else {
		zrecv.pcap_recv = pcst.ps_recv;
		zrecv.pcap_drop = pcst.ps_drop;
		zrecv.pcap_ifdrop = pcst.ps_ifdrop;
		zrecv.packet_counter = packet_counter;
	}
	return EXIT_SUCCESS;
}
