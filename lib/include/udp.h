#ifndef __UDP_H__
#define __UDP_H__

#include "ip.h"

/*
 * Control flags
 */
#ifndef DEBUG_UDP
#define DEBUG_UDP 0
#endif  // DEBUG_UDP
#ifndef DEBUG_UDP_CHECKSUM
#define DEBUG_UDP_CHECKSUM 0
#endif  // DEBUG_UDP_CHECKSUM
#ifndef DEBUG_UDP_FILTER
#define DEBUG_UDP_FILTER 0
#endif  // DEBUG_UDP_FILTER
#ifndef DEBUG_UDP_DUMP
#define DEBUG_UDP_DUMP 0
#endif  // DEBUG_UDP_DUMP

/*====================*
 ***** Parameters *****
 *====================*/
#define UDP_FILTER_PORT 0x3456

/*============================*
 ***** Protocol Constants *****
 *============================*/
#define IP_PROTO_UDP 0x11

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  uint16_t length;
  uint16_t chksum;
} myudp_hdr_t;

typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  myip_param_t ip;
} myudp_param_t;

/*========================*
 ***** Public Methods *****
 *========================*/
extern void udp_main(netdevice_t *p, uint8_t *pkt, int len);
extern void udp_send(netdevice_t *p, myudp_param_t udp_param, uint8_t *payload,
                     int payload_len);

#endif /* __UDP_H__ */
