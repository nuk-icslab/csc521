#ifndef __ARP_H__
#define __ARP_H__

#include "ip.h"
#include "netdevice.h"
#include "util.h"

/*
 * Control flags
 */
#ifndef DEBUG_ARP
#define DEBUG_ARP 0
#endif  // DEBUG_ARP
#ifndef DEBUG_ARP_REQUEST
#define DEBUG_ARP_REQUEST 0
#endif  // DEBUG_ARP_REQUEST
#ifndef DEBUG_ARP_REPLY
#define DEBUG_ARP_REPLY 0
#endif  // DEBUG_ARP_REPLY
#ifndef DEBUG_ARP_DUMP
#define DEBUG_ARP_DUMP 0
#endif  // DEBUG_ARP_DUMP
#ifndef DEBUG_ARPCACHE
#define DEBUG_ARPCACHE 0
#endif  // DEBUG_ARPCACHE

extern uint8_t myethaddr[ETH_ADDR_LEN];
extern uint8_t myipaddr[IPV4_ADDR_LEN];
extern uint8_t defarpip[IPV4_ADDR_LEN];

/*============================*
 ***** Protocol Constants *****
 *============================*/
#define ARP_ETH_TYPE 0x0100
#define ARP_OP_REQUEST 0x0100
#define ARP_OP_REPLY 0x0200
extern const uint8_t eth_broadcast_addr[ETH_ADDR_LEN];
extern const uint8_t eth_null_addr[ETH_ADDR_LEN];

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint16_t ethtype;
  uint16_t iptype;
  uint8_t ethlen;
  uint8_t iplen;
  uint16_t op;
  uint8_t srceth[ETH_ADDR_LEN];
  uint8_t srcip[IPV4_ADDR_LEN];
  uint8_t dsteth[ETH_ADDR_LEN];
  uint8_t dstip[IPV4_ADDR_LEN];
} myarp_t;

/*========================*
 ***** Public Methods *****
 *========================*/
extern void arp_request(netdevice_t *p, uint8_t *ip);
extern void arp_reply(netdevice_t *p, uint8_t *dsteth, uint8_t *dstip);
extern void arp_main(netdevice_t *p, uint8_t *pkt, unsigned int len);
extern void arp_send(netdevice_t *p, uint8_t *dst_ip, uint16_t eth_type,
                     uint8_t *payload, int payload_len);
extern void arp_resend(netdevice_t *p);

/*==============================*
 ***** Methods of ARP cache *****
 *==============================*/
extern uint8_t *arptable_existed(uint8_t *ip);
extern void arptable_add(uint8_t *ip, uint8_t *eth);

#endif /* __ARP_H__ */
