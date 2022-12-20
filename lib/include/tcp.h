#ifndef __TCP_H__
#define __TCP_H__

#include "ip.h"

/***
 ***	TCP
 ***/

/*
 * Control flags
 */
#ifndef DEBUG_TCP
#define DEBUG_TCP 0
#endif  // DEBUG_TCP
#ifndef DEBUG_TCP_DUMP
#define DEBUG_TCP_DUMP 0
#endif  // DEBUG_TCP_DUMP

/*============================*
 ***** Protocol Constants *****
 *============================*/
#define IP_PROTO_TCP 0x06
#define TCP_FG_URT 0x20
#define TCP_FG_ACK 0x10
#define TCP_FG_PSH 0x08
#define TCP_FG_RST 0x04
#define TCP_FG_SYN 0x02
#define TCP_FG_FIN 0x01
#define TCP_MIN_HLEN 0x50
#define TCP_DEF_WINDOW 1024

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  uint32_t seq;
  uint32_t ack;
  uint8_t hlen;
  uint8_t flags;
  uint16_t window;
  uint16_t chksum;
  uint16_t urgent;
} mytcp_hdr_t;

typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  myip_param_t ip;
} mytcp_param_t;

typedef void (*tcp_raw_handler)(myip_hdr_t *ip_hdr, mytcp_hdr_t *tcp_hdr,
                                uint8_t *data, int len);

/*========================*
 ***** Public Methods *****
 *========================*/
extern void tcp_main(netdevice_t *p, uint8_t *pkt, int len);
extern void tcp_syn(netdevice_t *p, mytcp_param_t tcp_param, uint8_t *payload,
                    int payload_len);
extern void tcp_set_raw_handler(tcp_raw_handler callback);

/*===========================*
 ***** Private Utilities *****
 *===========================*/
#define tcphlen(tcp) (((tcp)->tcp_hlen >> 4) << 2)
#define tcphlen_set(tcp, n) ((tcp)->tcp_hlen = (((n) >> 2) << 4))
#define tcpflag(tcp, flag) (((tcp)->tcp_flags & (flag)) != 0)
#define tcpflag_set(tcp, flag) ((tcp)->tcp_flags |= (flag))

#endif /* __TCP_H__ */
