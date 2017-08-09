/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_RECV_H
#define ZMAP_RECV_H

#include <pthread.h>
#include "ringbuffer.h"
#define PCAP_BUFFER_SIZE (20*1024*1024)

extern pthread_mutex_t recv_mutex;

typedef struct recv_arg {
	uint32_t cpu;
	ringbuffer_t* ring;
} recv_arg_t;

int recv_update_stats(void);
int recv_run(pthread_mutex_t *recv_ready_mutex, recv_arg_t* thread_args);
void recv_init_shared();
void recv_cleanup_shared();

#endif /* ZMP_RECV_H */
