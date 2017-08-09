#include "ipdata.h"
#include "../lib/logger.h"

#include <stdlib.h>
#include <math.h>
#include <string.h>

#define ARRAYLENGTH 65536

/**
 * @brief create_InputTable  Create an array of skiplists
 * @return
 */
skipList* create_InputTable(void) {
    skipList* myInputTable;
    // create a skiplist for all 2^16 possible prefixes (2byte)
    myInputTable = malloc(sizeof(skipList)*ARRAYLENGTH); // create table with size of 2^16
    if(myInputTable == NULL) {
        return NULL;
    }
    // initial the skip lists
    for(int i=0; i<ARRAYLENGTH; i++) {
        myInputTable[i].head = NULL;
        myInputTable[i].size = 0;
        myInputTable[i].level = 1;
    }
    return myInputTable;
}

void link_InputTable(skipList* myInputTable) {
    // Optimal height: log(size)
    for(int i=0; i<ARRAYLENGTH; i++) {
        int height = ceil(log2(myInputTable[i].size));
        myInputTable[i].level = height;

        if(myInputTable[i].size>0) {
            //log_debug("ipdata", "SIZE %d HEIGHT %d",myInputTable[i].size, height);
        }
        for(int j=1; j<=height; j++) {
            //log_debug("ipdata","j=%i",j);
            dataElement* cur = myInputTable[i].head;
            dataElement* next;
            int pos = 0;
            while(cur != NULL) {
                // check if we have to create a new link memory
                if(cur->height == 0 && pos%2==0) {
                    int exponent = height;
                    while(pos%((int)(pow(2,exponent)))!=0) {
                        exponent--;
                    }
                    //log_debug("ipdata","CREATE MEMORY %i - %i",pos,exponent);
                    // create the memory to hold the links
                    dataElement** jump = malloc(sizeof(dataElement*)*(exponent+1));
                    // copy old data
                    jump[0] = cur->jump[0];
                    free(cur->jump);
                    cur->jump = jump;
                    cur->height=exponent;
                }
                // jump 2 steps of the highest defined link
                if(cur->jump[j-1] == NULL) {
                    next = NULL;
                    //log_debug("ipdata","%d link to NULL",pos);
                }
                else {
                    next = cur->jump[j-1]->jump[j-1];
                    //log_debug("ipdata","%d link to %d -> %i",pos,pos+(int)floor(pow(2,j-1)*2), next);
                }
                cur->jump[j] = next;
                cur = next;
                pos+=pow(2,j);
            }
        }
    }
}

void destroy_InputTable(skipList* myInputTable) {
    for(int i=0; i<ARRAYLENGTH; i++) {
        dataElement* node = myInputTable[i].head;
        while(node != NULL) {
            dataElement* next = node->jump[0];
            free(node->data);
            free(node->jump);
            free(node);
            node = next;
        }
    }
    free(myInputTable);
}

/**
 * @brief insert_InputTable  We get an ip address and a string with the relevant data and save it into the table
 */
void insert_InputTable(skipList* myInputTable,uint32_t ip, char* data) {
    uint16_t ident =  (uint16_t)(ip >> 16);
    //log_debug("ipdata","Input %u,%s IDENT %u",ip,data,ident);
    dataElement* dataPtr = malloc(sizeof(dataElement));
    dataPtr->ip = ip;
    dataPtr->data = data;
    dataPtr->jump = (dataElement**)malloc(sizeof(dataElement*));
    dataPtr->jump[0] = NULL;
    dataPtr->height = 0;

    skipList* listPtr = &myInputTable[ident];
    dataElement* cur = listPtr->head;
    // list empty
    if(cur == NULL) {
        listPtr->head = dataPtr;
        listPtr->size++;
        return;
    }
    // search for last element that has smaller ip and link to that
    dataElement* last = listPtr->head;
    while(1) {
        // we found an object with bigger ip or the end
        if(cur == NULL || cur->ip >ip) {
            dataPtr->jump[0] = cur;
            // are we the new head ?
            if(cur == listPtr->head) {
                listPtr->head = dataPtr;
            }
            else {
                last->jump[0] = dataPtr;
            }
            break;
        }
        else {
            last = cur;
            cur = cur->jump[0];
        }
    }
    listPtr->size++;
}

char* search_InputTable(skipList* myInputTable, uint32_t ip) {
    uint16_t ident =  (uint16_t)(ip >> 16);
    skipList* listPtr = &myInputTable[ident];
    dataElement* cur = listPtr->head;
    // no entries in skiplist
    if(cur == NULL) {
        //log_debug("ipdata","SEARCH not found(empty) %u ", ip);
        return NULL;
    }
    for(int lvl=(int)cur->height; lvl>=0; lvl--) {
        //log_debug("ipdata","Level %i",lvl);
        while(cur->jump[lvl] != NULL && cur->jump[lvl]->ip <= ip) {
            cur = cur->jump[lvl];
        }
    }
    if(cur != NULL && cur->ip == ip) {
        //log_debug("ipdata","SEARCH FOUND %u ", ip);
        return cur->data;
    }
    else {
        //log_debug("ipdata","SEARCH not found %u ", ip);
        return NULL;
    }
}
