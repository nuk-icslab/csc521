#ifndef __ICMP_H__
#define __ICMP_H__

#include "ip.h"
#include "mypcap.h"

/*============================*
 ***** Protocol Constants *****
 *============================*/
#define IP_PROTO_ICMP 0x01
#define ICMP_TYPE_ECHO_REQ 0x08
#define ICMP_TYPE_ECHO_REP 0x00
#define ICMP_TYPE_DST_UN 0x03
#define ICMP_TYPE_REDIR 0x05
#define ICMP_TYPE_TIME_EXCD 0x0b

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t chksum;
  uint16_t id;
  uint16_t seq;
} myicmp_hdr_t;

/*========================*
 ***** Public Methods *****
 *========================*/
extern void icmp_main(mypcap_t *p, uint8_t *pkt, int len);
extern void icmp_ping(mypcap_t *p, uint8_t *dstip);

#endif /* __ICMP_H__ */
