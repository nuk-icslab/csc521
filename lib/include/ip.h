#ifndef __IP_H__
#define __IP_H__

#include <pcap.h>

#include "netdevice.h"

/*
 * Control flags
 */
#ifndef DEBUG_IP
#define DEBUG_IP 0
#endif  // DEBUG_IP
#ifndef DEBUG_IP_CHECKSUM
#define DEBUG_IP_CHECKSUM 0
#endif  // DEBUG_IP_CHECKSUM
#ifndef DEBUG_IP_DUMP
#define DEBUG_IP_DUMP 0
#endif  // DEBUG_IP_DUMP

/*====================*
 ***** Parameters *****
 *====================*/
extern uint8_t myipaddr[IPV4_ADDR_LEN];
extern uint8_t myrouterip[IPV4_ADDR_LEN];
extern uint8_t mynetmask[IPV4_ADDR_LEN];

/*============================*
 ***** Protocol Constants *****
 *============================*/
#define IP_VERSION 4
#define IP_MIN_HLEN 5
#define IP_MAX_TTL 255
#define MAX_IP_PAYLOAD_LEN (MAX_CAP_LEN - sizeof(myip_hdr_t))

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint8_t verhlen;
  uint8_t servicetype;
  uint16_t length;

  uint16_t identification;
  uint16_t fragoff;

  uint8_t ttl;
  uint8_t protocol;
  uint16_t chksum;

  uint8_t srcip[IPV4_ADDR_LEN];
  uint8_t dstip[IPV4_ADDR_LEN];

} myip_hdr_t;

/*========================*
 ***** Public Methods *****
 *========================*/
typedef struct {
  uint8_t protocol;
  uint8_t dstip[IPV4_ADDR_LEN];
  uint8_t srcip[IPV4_ADDR_LEN];
} myip_param_t;

extern void ip_send(netdevice_t *p, myip_param_t *ip_param, uint8_t *payload,
                    int payload_len);
extern void ip_main(netdevice_t *p, uint8_t *pkt, int len);

/*===========================*
 ***** Private Utilities *****
 *===========================*/
#define hlen(ip) ((ip)->verhlen & 0x0f)
#define ver(ip) ((ip)->verhlen >> 4)
#define verhlen(ver, hlen) (((ver) << 4) + (hlen))
extern uint16_t ip_checksum(myip_hdr_t *ip);

#endif /* __IP_H__ */
