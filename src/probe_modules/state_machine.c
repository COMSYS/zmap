#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#include "state_machine.h"
#include "logger.h"
#include "state.h"
#include "probe_modules.h"

struct StateTable* myStateTable;

pthread_t cleanup_thread;

pthread_mutex_t statetable_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t get_HashValue(uint32_t server_ip, uint16_t local_port, uint32_t mask ) {
    uint32_t hash = (server_ip ^ local_port); // foreign ip XOR local port
    hash ^= hash >> 16;
    hash ^= hash >> 8;
    return hash & mask;
}


void reset_StateData(struct StateData* myData) {
	if(myData == NULL)
		return;
    if(myData->info != NULL) {
        free(myData->info);
    }

    myData->info = NULL;
    myData->port = 0;
    myData->sqn = 0;
    myData->ssqn = 0;
    myData->state = STATE_UNUSED;
    myData->lastActive = 0;
}

struct StateList* create_StateList() {
    struct StateList* myList = (struct StateList*) malloc(sizeof(struct StateList));
    myList->head = NULL;
    myList->tail = NULL;
    myList->active = 0;
    return myList;
}

void destroy_StateList(struct StateList* myList) {
    struct ListElem* cur = myList->head;
    struct ListElem* next =  NULL;
    while(cur != NULL) {
        next = cur->next;    //save the link to the next element
        reset_StateData(cur->data);
        free(cur->data);     //free the data of the element
        free(cur);          //free the element
        cur = next;
    }
 //   free(myList);
}

struct StateData* addto_StateList(uint32_t server_ip, uint16_t local_port, struct StateList* myList) {
    struct StateData* myData = (struct StateData*) malloc(sizeof(struct StateData));
    memset(myData, 0, sizeof(struct StateData));
    
    struct ListElem* myListelem = (struct ListElem*) malloc(sizeof(struct ListElem));
    myListelem->data = myData;
	assert(myData->info == NULL);
    myListelem->prev = NULL;
    myListelem->next = NULL;

    reset_StateData(myData);
    myData->ip = server_ip;
    myData->port = local_port;
    myData->lastActive = now();
	pthread_mutex_init(&myData->state_lock, NULL);

    if(myList->tail != NULL) {
        myList->tail->next = myListelem;
        myListelem->prev = myList->tail;
        myList->tail = myListelem;
    }
    else {
        myList->head = myListelem;
        myList->tail = myListelem;
    }
    myData->state = STATE_START;
    return myData;
}

struct StateData* get_StateDataCollision(uint32_t server_ip, uint16_t local_port, struct StateList* tbl, struct StateTable* myTable) {
    struct ListElem* cur = tbl->head;
    while(cur != NULL) {
        if(cur->data->ip == server_ip && cur->data->port == local_port) {
            return cur->data;
        }
		if(cur->data->lastActive < now() - myTable->timeout) {
			struct ListElem* nxt = cur->next;
			if(cur->prev != NULL) {
				cur->prev->next = cur->next;
			}
			else {
				tbl->head = cur->next;
			}
			if(cur->next != NULL) {
				cur->next->prev = cur->prev;
			}
			else {
				tbl->tail = cur->prev;
			}
			reset_StateData(cur->data);
			free(cur->data);
			free(cur);
			myTable->active--;
			tbl->active--;
			cur = nxt;
		}else {
			cur = cur->next;
		}
    }
    return NULL;
}

struct StateData* get_StateData(uint32_t server_ip, uint16_t local_port,struct StateTable* myTable) {
    if(myTable == NULL || server_ip == 0 || local_port == 0) {
        return NULL;
    }
	if(cleanup_thread == 0) {
		pthread_create(&cleanup_thread, NULL, drop_Inactive, (void*)myTable);
		pthread_detach(cleanup_thread);
	}
    uint32_t myHash = get_HashValue(server_ip, local_port, myTable->mask);
    if(myHash < myTable->length) {
		struct StateList* tbl = &myTable->data[myHash];
        return get_StateDataCollision(server_ip, local_port, tbl, myTable);
    } else {
        return NULL;
    }
}



struct StateTable* create_StateTable(uint32_t initial_size, uint32_t timeout) {
    struct StateTable *myTable;
    myTable = (struct StateTable*) malloc(sizeof(struct StateTable));
    if (myTable == NULL) {
        return NULL;
    }
    myTable->timeout = timeout;
    // Search for nearest power of 2 to initial_size
    unsigned int n = initial_size;
    unsigned count = 0;
    if (!(n && !(n&(n-1)))) {
        while( n != 0)
        {
            n  >>= 1;
            count += 1;
        }
        n = 1<<count;
    }
	if (n <= 1) {
		n = 2;
	}
    myTable->length = n;
    myTable->data = NULL;
    while (myTable->data == NULL && myTable->length > 1) {
        myTable->data = (struct StateList*) malloc(myTable->length * sizeof(struct StateList));
        if (myTable->data == NULL) {    // alloc failed
            myTable->length >>= 1;      // reduce length of alloc
        }
    }
	if (myTable->data == NULL) {
		free(myTable);
		return NULL;
	}
    myTable->mask = myTable->length-1;
	
	log_info("state_machine", "Using a hashtable of size %d\n", myTable->length);
    memset(myTable->data, 0 , myTable->length*sizeof(struct StateList));
    // we allocated space, initialize values for the elements:
    for(unsigned int i=0; i<myTable->length; i++) {
        struct StateList* ptr = &(myTable->data[i]);
		ptr->head = NULL;
		ptr->tail = NULL;
		ptr->active = 0;
    }

    myTable->active = 0;
	cleanup_thread = 0;
//    myTable->collisionList = create_StateList();
    return myTable;
}

void destroy_StateTable(struct StateTable* myTable) {
    if(myTable == NULL) {
        return;
    }
    else {
        //destroy_StateList(myTable->collisionList);
        // free pointers
        for(unsigned int i=0; i<myTable->length; i++) {
            struct StateList* ptr = &myTable->data[i];
			destroy_StateList(ptr);
        }
        free(myTable->data);
        free(myTable);
    }
}


struct StateData* insert_StateData(uint32_t server_ip, uint16_t local_port ,struct StateTable* myTable) {
    if(myTable == NULL || server_ip == 0 || local_port == 0) {
        log_trace("state_machine","Incorrect input");
        assert(false && "Some idiot made wrong assumptions about serverip or local_port");
    }
    else {
        uint32_t myHash = get_HashValue(server_ip, local_port, myTable->mask);
        if(myHash < myTable->length) {
			struct StateList* tbl = &myTable->data[myHash];
			StateData* ptr = addto_StateList(server_ip, local_port, tbl);
			tbl->active++;
			myTable->active++;
			return ptr;
		}else {
            assert(false && "Someone made a mistake with the hash");
        }
    }
}

void remove_StateData(uint32_t server_ip, uint16_t local_port,struct StateTable* myTable) {
    if(myTable == NULL || server_ip == 0 || local_port == 0) {
        return;
    }
    uint32_t myHash = get_HashValue(server_ip, local_port, myTable->mask);
    if(myHash < myTable->length) {
		struct StateList* tbl = &myTable->data[myHash];
		struct ListElem* cur = tbl->head;
        

		while(cur != NULL) {
			if(cur->data->ip == server_ip && cur->data->port == local_port) {
				if(cur->prev != NULL) {
					cur->prev->next = cur->next;
				}
				else {
					tbl->head = cur->next;
				}

				if(cur->next != NULL) {
					cur->next->prev = cur->prev;
				}
				else {
					tbl->tail = cur->prev;
				}
				reset_StateData(cur->data);
				free(cur->data);
				cur->data = NULL;
				free(cur);
				myTable->active--;
				tbl->active--;
				return;
			}
			cur = cur->next;
        }
    }
}

void update_Timeout(struct StateData* myData) {
    myData->lastActive = now();
}


/** Create our Table */
void state_myinit(uint32_t init_size, uint32_t timeout) {
    myStateTable = create_StateTable(init_size, timeout);
}

void state_mydestroy() {
    destroy_StateTable(myStateTable);
}


/** Timeout functionality, Clean up the list*/

void* drop_Inactive(void* args) {
	struct StateTable* myTable = args;
while (1) {
	for (uint32_t i = 0; i < myTable->length; i++) {
		struct StateList* tbl = &myTable->data[i];
		pthread_mutex_lock(&statetable_lock);
		time_t curTime = now();
		struct ListElem* cur = tbl->head;
        
        if (tbl->head != NULL)
            assert(tbl->head->prev == NULL && "Head pointer's prev pointer does not point to zero");
        
        if (tbl->tail != NULL)
            assert(tbl->tail->next == NULL && "Tail pointer's next pointer does not point to zero");
        
        
		while(cur != NULL) {
			
			if(cur->data->lastActive < curTime - myTable->timeout){
				if(cur->prev != NULL) {
					cur->prev->next = cur->next;
				}
				else {
					tbl->head = cur->next;
				}
				if(cur->next != NULL) {
					cur->next->prev = cur->prev;
				}
				else {
					tbl->tail = cur->prev;
				}
				struct ListElem* tmp = cur->next;
				// send our timeout event to the probe module to collect&process data if necessary
				if(zconf.probe_module->process_timeout) {
					zconf.probe_module->process_timeout(cur->data);
				}
				
				reset_StateData(cur->data);
				free(cur->data);
				cur->data = NULL;
				free(cur);
				myTable->active--;
				tbl->active--;
				cur = tmp;
			}
			else {
				cur = cur->next;
			}
		}
		pthread_mutex_unlock(&statetable_lock);
		usleep(2); // sleep this thread for 200ms
	}
    usleep(1);
}
	log_debug("state_table", "Currently total active %d\n", myTable->active);
	cleanup_thread = 0;
	return NULL;
}
