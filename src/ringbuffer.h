#ifndef RINGBUFFER_H_INCLUDED
#define RINGBUFFER_H_INCLUDED

#include <stdint.h>



// ignore all values and don't fiddle with them
typedef struct
{
	//uint64_t sent;              // number of packets written on the buffer (and sent)
	uint32_t ring_start;        // start of the used part
	uint32_t ring_end;          // end of the used part
	uint32_t num_entries;         // size of the ring (in number of entries, not bytes)
	uint32_t entry_size;      // size of one data object in bytes
//	uint32_t num_used;       // number of currently used objects
	uint8_t* buffer;          // pointer to the data
	pthread_mutex_t ring_mutex;  // this is used to lock this ring
} ringbuffer_t;

extern ringbuffer_t* all_rings;

/**
 *
 * Use these to synchronize all thread unsafe functions
 *
 */
void ringbuffer_lock(ringbuffer_t* ringbuffer);

void ringbuffer_unlock(ringbuffer_t* ringbuffer);

/**
 * create a new ringbuffer with num_entries entries
 * each entry has the size entry_size, you may preinitialize
 * all entries with buf_init having buf_init_len
 * returns pointer to the ringbuffer for further method calls
 */
int ringbuffer_create(ringbuffer_t* ringbuffer, uint32_t num_entries, uint32_t entry_size, uint8_t* buf_init, uint32_t buf_init_len);

/**
 *
 * Destroyes a ringbuffer created via ringbuffer_create
 */
void ringbuffer_destroy(ringbuffer_t* ringbuffer);


/**
 * Checks if the ringbuffer is full
 * returns: 1 if full, 0 otherwise
 *
 * This call is not threadsafe!
 */
int ringbuffer_is_full(ringbuffer_t* ringbuffer);

/**
 * Checks if the ringbuffer is empty
 * returns: 1 if empty, 0 otherwise
 *
 * This call is not threadsafe!
 */
int ringbuffer_is_empty(ringbuffer_t* ringbuffer);


/**
 * Gives the fill level of the ring
 *
 * returns 0.0 <= filllevel <= 1.0
 *
 * This call is not threadsafe
 */
float ringbuffer_fill_level(ringbuffer_t* ringbuffer);

/**
 *
 * Returns the oldest element in the ringbuffer and removes
 * it from the buffer.
 * data is an output parameter which will point to the start
 * of the data.
 * the method returns the size of the actual size of the data
 * or 0 if the buffer is empty
 *
 * This call is not threadsafe!
 */
uint32_t ringbuffer_pop(ringbuffer_t* ringbuffer, uint8_t** data);


/**
 *
 * Allocates a new space in the buffer, passing you a pointer to
 * a possibly previously used data field via the data parameter.
 *
 * The memory region behind current_len will be filled with the size
 * of the data how it was previously initialized or used.
 *
 * Method return the maximum amount of data that is available or 0
 * if the ring is full.
 *
 * This call is not threadsafe and it must follow a ringbuffer_commit
 *
 */
uint32_t ringbuffer_reserve(ringbuffer_t* ringbuffer, uint8_t** data, uint32_t* current_len);


/**
 *
 * Commit the previously reserved buffer (via ringbuffer_reserve) space
 * to the ringbuffer.
 *
 * new_len denotes the new length of the data
 *
 * This call is not threadsafe!
 *
 */
void ringbuffer_commit(ringbuffer_t* ringbuffer, uint32_t new_len);

#endif
