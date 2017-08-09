#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H


#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define STATE_UNUSED 0
#define STATE_START 1
#define STATE_SYNACK 2
#define STATE_ACK 3
#define STATE_ACKCHECK 16
#define STATE_FAIL 254
#define STATE_FINISHED 255

// Data structure for the state machine
typedef struct StateData{
    void* info;         // void pointer to store additional data, will be freed when StateData is destroyed
                        // set info to null if no additional information is used in the probe module
    time_t lastActive;
    uint32_t ip;        // store the ip of the server
    uint32_t sqn;       // store our sequence number (used for next packet)
    uint32_t ssqn;      // server sequence number (expect this sqn in next packet)
    uint16_t port;       // local port
	uint32_t reported_mss;  // mss as reported in syn+ack from dest
	uint32_t estimated_mss;  // mss estimated from number of bytes received in the first packet
    uint32_t probe_num;
    uint8_t state;      // store the state of the connection
	pthread_mutex_t state_lock;
} StateData;

typedef struct StateTable{
    struct StateList *data;    // pointer to our data array
//    struct StateList *collisionList; // List for collisions
    uint32_t length;            // length of the data array
    uint32_t active;
    uint32_t mask;              // mask that is used for hashing (according to length)
    uint32_t timeout;           // timeout until inactive connections are removed (and reported as fail?)
} StateTable;

// Data Structure for collision List (double linked list)
typedef struct ListElem {
    struct StateData *data;         // Data element
    struct ListElem  *next;         // next element
    struct ListElem *prev;          // previous element
}ListElem;

// the collision list
typedef struct StateList {
    struct ListElem *head;          // head element
    struct ListElem *tail;          // tail element
    uint32_t active;
}StateList;

extern StateTable *myStateTable;

void state_myinit(uint32_t init_size, uint32_t timeout);
void state_mydestroy();
struct StateData*  insert_StateData(uint32_t server_ip, uint16_t local_port ,struct StateTable* myTable);
void remove_StateData(uint32_t server_ip, uint16_t local_port,struct StateTable* myTable);
struct StateData* get_StateData(uint32_t server_ip, uint16_t local_port,struct StateTable* myTable);
void update_Timeout(struct StateData* myData);
void* drop_Inactive(void* args);
#endif
