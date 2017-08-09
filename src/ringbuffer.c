#include "../lib/xalloc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "logger.h"
#include "ringbuffer.h"


ringbuffer_t* all_rings;


int ringbuffer_create(ringbuffer_t* ringbuffer, uint32_t num_entries, uint32_t entry_size, uint8_t* buf_init, uint32_t buf_init_len) {
	
	if(entry_size < buf_init_len)
		return 0;
	
	
//	ringbuffer_t* ringbuffer = xmalloc(sizeof(ringbuffer_t));
	memset(ringbuffer, 0, sizeof(ringbuffer_t));
	// we always leave one slot empty to differenciate empty and full
	ringbuffer->num_entries = num_entries+1;
	ringbuffer->entry_size = entry_size;
	ringbuffer->ring_start = 0;
	ringbuffer->ring_end = 0;
	pthread_mutex_init(&ringbuffer->ring_mutex, NULL);

	ringbuffer->buffer = xcalloc(ringbuffer->num_entries, (ringbuffer->entry_size+sizeof(entry_size)));
	if (ringbuffer->buffer == NULL) {
		log_fatal("ringbuffer", "Could not allocate memory for ringbuffer");
		exit(EXIT_FAILURE);
	}
	// preinit
	if (buf_init != NULL) {
		int pos = 0;
		for (uint32_t i = 0; i < ringbuffer->num_entries; i++, pos += ringbuffer->entry_size+sizeof(entry_size)) {
			*(ringbuffer->buffer+pos) = buf_init_len;
			memcpy(ringbuffer->buffer+pos+sizeof(entry_size), buf_init, buf_init_len);
		}
	}else {
		int pos = 0;
		for (uint32_t i = 0; i < ringbuffer->num_entries; i++, pos += ringbuffer->entry_size+sizeof(entry_size)) {
			*(ringbuffer->buffer+pos) = entry_size;
			//memcpy(ringbuffer->buffer+pos+sizeof(entry_size), buf_init, buf_init_len);
		}

	}
	
	return 1;
}

void ringbuffer_lock(ringbuffer_t* ringbuffer) {
	pthread_mutex_lock(&ringbuffer->ring_mutex);
}

void ringbuffer_unlock(ringbuffer_t* ringbuffer) {
	pthread_mutex_unlock(&ringbuffer->ring_mutex);
}

void ringbuffer_destroy(ringbuffer_t* ringbuffer) {
	if (ringbuffer == NULL)
		return;
	free(ringbuffer->buffer);
	free(ringbuffer);
}

int ringbuffer_is_full(ringbuffer_t* ringbuffer) {  // thread unsafe
//	log_info("ringbuffer", "FULL: ring_end at %u ring_start at %u cond: %u entries %u", ringbuffer->ring_end, ringbuffer->ring_start, ((ringbuffer->ring_end + 1) % ringbuffer->num_entries), ringbuffer->num_entries);
	return (((ringbuffer->ring_end + 1) % ringbuffer->num_entries) == ringbuffer->ring_start);
}

int ringbuffer_is_empty(ringbuffer_t* ringbuffer) {  // thread unsafe
//	log_info("ringbuffer", "EMPTY: ring_end at %u ring_start at %u", ringbuffer->ring_end, ringbuffer->ring_start);
	return (ringbuffer->ring_end == ringbuffer->ring_start);
}

// thread unsafe
float ringbuffer_fill_level(ringbuffer_t* ringbuffer) {
	if(ringbuffer->ring_end >= ringbuffer->ring_start) {
		return (ringbuffer->ring_end - ringbuffer->ring_start) / (float)ringbuffer->num_entries;
	}else {
		return (ringbuffer->num_entries - (ringbuffer->ring_start - ringbuffer->ring_end) ) / (float)ringbuffer->num_entries;
	}
}

uint32_t ringbuffer_pop(ringbuffer_t* ringbuffer, uint8_t** data) { // thread unsafe
	if (ringbuffer_is_empty(ringbuffer)) {
		return 0;
	}
	uint8_t* first = ringbuffer->buffer+((ringbuffer->entry_size+sizeof(uint32_t))*(ringbuffer->ring_start));
	uint32_t len = *(uint32_t*)first;
	*data = first+sizeof(uint32_t);
	ringbuffer->ring_start = (ringbuffer->ring_start + 1) % ringbuffer->num_entries;
	return len;
}

uint32_t ringbuffer_reserve(ringbuffer_t* ringbuffer, uint8_t** data, uint32_t* current_len) { // totally not threadsafe
	if (ringbuffer_is_full(ringbuffer)) {
		return 0;
	}
	uint8_t* next = ringbuffer->buffer+((ringbuffer->entry_size+sizeof(uint32_t))*(ringbuffer->ring_end));
	uint32_t len = *(uint32_t*)next;
	*data = next+sizeof(uint32_t);
	//ringbuffer->ring_start = (ringbuffer->ring_start + 1) % ringbuffer->num_entries;
	if (current_len != NULL)
		*current_len = len;
	return ringbuffer->entry_size;
}

void ringbuffer_commit(ringbuffer_t* ringbuffer, uint32_t new_len) { // totally not threadsafe
	uint8_t* next = ringbuffer->buffer+((ringbuffer->entry_size+sizeof(uint32_t))*(ringbuffer->ring_end));
//	log_trace("ringbuffer", "Setting length to %d", new_len);
	*(uint32_t*)next = new_len;
	ringbuffer->ring_end = (ringbuffer->ring_end + 1) % ringbuffer->num_entries;
}

