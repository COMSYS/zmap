#ifndef IP_DATA_H
#define IP_DATA_H

#include <stdint.h>

typedef struct dataElement{
    struct dataElement** jump; // store the jumps, including next
    uint32_t ip;        // ip as key
    char* data;         // value
    uint8_t height;     // number of links
} dataElement;

typedef struct skipList{
    dataElement* head;  // first node
    uint8_t level;      // # of links for a node
    uint32_t size;      // number of nodes stored
} skipList;

skipList* create_InputTable(void);
void link_InputTable(skipList* myInputTable);
void destroy_InputTable(skipList* myInputTable);
void insert_InputTable(skipList* myInputTable,uint32_t ip, char* data);
char* search_InputTable(skipList* myInputTable, uint32_t ip);

#endif
