/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "recv.h"

#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"

#include <pthread.h>
#include <unistd.h>

#include "recv-internal.h"
#include "state.h"
#include "validate.h"
#include "fieldset.h"
#include "ringbuffer.h"
#include "expression.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"

static u_char fake_eth_hdr[65535];

// bitmap of observed IP addresses
static uint8_t **seen = NULL;

// this synchronizes all receive threads
pthread_mutex_t recv_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_packet(uint32_t buflen, const u_char *bytes, ringbuffer_t* ring) {
	if ((sizeof(struct ip) + (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header))) > buflen) {
		// buffer not large enough to contain ethernet
		// and ip headers. further action would overrun buf
		return;
	}
	struct ip *ip_hdr = (struct ip *) &bytes[(zconf.send_ip_pkts ? 0 : sizeof(struct ether_header))];

	uint32_t src_ip = ip_hdr->ip_src.s_addr;

	uint32_t validation[VALIDATE_BYTES/sizeof(uint8_t)];
	// TODO: for TTL exceeded messages, ip_hdr->saddr is going to be different
	// and we must calculate off potential payload message instead
	validate_gen(ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr, (uint8_t *) validation);

	if (!zconf.probe_module->validate_packet(ip_hdr, buflen - (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header)),
				&src_ip, validation)) {
		zrecv.validation_failed++;
		return;
	} else {
		zrecv.validation_passed++;
	}
	// woo! We've validated that the packet is a response to our scan
	// track whether this is the first packet in an IP fragment.
	if (ip_hdr->ip_off & IP_MF) {
		zrecv.ip_fragments++;
	}

	fieldset_t *fs = fs_new_fieldset();
	fs_add_ip_fields(fs, ip_hdr);
	// HACK:
	// probe modules (for whatever reason) expect the full ethernet frame
	// in process_packet. For VPN, we only get back an IP frame.
	// Here, we fake an ethernet frame (which is initialized to
	// have ETH_P_IP proto and 00s for dest/src).
	if (zconf.send_ip_pkts) {
		if (buflen > sizeof(fake_eth_hdr)) {
			buflen = sizeof(fake_eth_hdr);
		}
		memcpy(&fake_eth_hdr[sizeof(struct ether_header)], bytes, buflen);
		bytes = fake_eth_hdr;
	}
	
	if (zconf.probe_module->state_aware) {
		uint8_t proccess_val = zconf.probe_module->process_packet_aware(bytes, buflen, fs, validation, ring);
		if(zsend.complete) { // we are actually done sending but we still receive packets
			zsend.finish = now();
		}
		if(proccess_val != EXIT_SUCCESS) {
			fs_free(fs);
			return;
		}

	}else {
		zconf.probe_module->process_packet(bytes, buflen, fs, validation);
	}
	
	// we need to protect the seen bitmap and the counters
	pthread_mutex_lock(&recv_mutex);
	
	int is_repeat = pbm_check(seen, ntohl(src_ip));
	fs_add_system_fields(fs, is_repeat, zsend.complete);
	int success_index = zconf.fsconf.success_index;
	assert(success_index < fs->len);
	int is_success = fs_get_uint64_by_index(fs, success_index);

	if (is_success) {
		zrecv.success_total++;
		if (!is_repeat) {
			zrecv.success_unique++;
			pbm_set(seen, ntohl(src_ip));
		}
		if (zsend.complete) {
			zrecv.cooldown_total++;
			if (!is_repeat) {
				zrecv.cooldown_unique++;
			}
		}
	} else {
		zrecv.failure_total++;
	}
	// probe module includes app_success field
	if (zconf.fsconf.app_success_index >= 0) {
		int is_app_success = fs_get_uint64_by_index(fs,
				zconf.fsconf.app_success_index);
		if (is_app_success) {
			zrecv.app_success_total++;
			if (!is_repeat) {
				zrecv.app_success_unique++;
			}
		}
	}
	// all counters and repitition check done
	pthread_mutex_unlock(&recv_mutex);
	
	
	fieldset_t *o = NULL;
	// we need to translate the data provided by the probe module
	// into a fieldset that can be used by the output module
	if (!is_success && zconf.filter_unsuccessful) {
		goto cleanup;
	}
	if (is_repeat && zconf.filter_duplicates) {
		goto cleanup;
	}
	if (!evaluate_expression(zconf.filter.expression, fs)) {
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
	if (zconf.output_module && zconf.output_module->update
			&& !(zrecv.success_unique % zconf.output_module->update_interval)) {
		// ToDo: check if this locking is required
		pthread_mutex_lock(&recv_mutex);
		zconf.output_module->update(&zconf, &zsend, &zrecv);
		pthread_mutex_unlock(&recv_mutex);
	}
}


// this happens only once for all threads
void recv_init_shared() {
	// initialize paged bitmap
	seen = pbm_init();
	
	if (!zconf.dryrun) {
		recv_init();
	}
}


int recv_run(pthread_mutex_t *recv_ready_mutex, recv_arg_t* thread_args)
{
	log_trace("recv", "recv thread started");
	log_debug("recv", "capturing responses on %s", zconf.iface);

	if (zconf.send_ip_pkts) {
		struct ether_header *eth = (struct ether_header *) fake_eth_hdr;
		memset(fake_eth_hdr, 0, sizeof(fake_eth_hdr));
		eth->ether_type = htons(ETHERTYPE_IP);
	}


	if (zconf.filter_duplicates) {
		log_debug("recv", "duplicate responses will be excluded from output");
	} else {
		log_debug("recv", "duplicate responses will be included in output");
	}
	if (zconf.filter_unsuccessful) {
		log_debug("recv", "unsuccessful responses will be excluded from output");
	} else {
		log_debug("recv", "unsuccessful responses will be included in output");
	}

	pthread_mutex_lock(recv_ready_mutex);
	zconf.recv_ready = 1;
	pthread_mutex_unlock(recv_ready_mutex);
	zrecv.start = now();
	if (zconf.max_results == 0) {
		zconf.max_results = -1;
	}

	do {
		if (zconf.dryrun) {
			sleep(1);
		} else {
			recv_packets(thread_args->ring);
			if (zconf.max_results && zrecv.success_unique >= zconf.max_results) {
				break;
			}
		}
	} while (!(zsend.complete && (now()-zsend.finish > zconf.cooldown_secs)));
	zrecv.finish = now();
	// get final pcap statistics before closing
	pthread_mutex_lock(&recv_mutex);
	recv_update_stats();
	pthread_mutex_unlock(&recv_mutex);

	log_debug("recv", "thread finished");
	return 0;
}

