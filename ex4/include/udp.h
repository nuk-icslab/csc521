#ifndef __UDP_H__
#define __UDP_H__

#include "dns.h"
#include "ip.h"

/*====================*
 ***** Parameters *****
 *====================*/
#define UDP_FILTER_PORT DEF_DNS_UDP_SRCPORT

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
extern void udp_main(mypcap_t *p, uint8_t *pkt, int len);
extern void udp_send(mypcap_t *p, myudp_param_t udp_param, uint8_t *payload,
                     int payload_len);

#endif /* __UDP_H__ */
