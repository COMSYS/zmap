#ifndef TCP_CONNECTION_H
#define TCP_CONNECTION_H
#include <stdint.h>
#include <unistd.h>


uint32_t tcp_buildAck(const uint8_t *packet, uint8_t* buf, uint32_t max_len);
uint32_t tcp_buildAck_with_acknum(const uint8_t *packet, uint32_t ack_num, uint8_t* buf, uint32_t max_len);
uint32_t tcp_buildRst(const uint8_t *packet, uint8_t* buf, uint32_t max_len);
uint32_t tcp_getPayloadLength(const uint8_t *buf);
uint8_t* tcp_buildData(const uint8_t *packet, uint8_t offset);

#endif
