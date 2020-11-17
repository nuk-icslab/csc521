#ifndef __ARP_H__
#define __ARP_H__

#include <pcap/pcap.h>
#include "common.h"
#include "ip.h"

#define ARP_PADDING	(46-sizeof(myarp_t))

#define ARP_ETH_TYPE 0x0100
#define ARP_OP_REQUEST 0x0100
#define ARP_OP_REPLY 0x0200

/***
 *** ARP
 ***/

typedef struct {
	uint16_t	ethtype;
	uint16_t	iptype;
	uint8_t	ethlen;
	uint8_t	iplen;
	uint16_t	op;
	uint8_t	srceth[ETH_ADDR_LEN];
	uint8_t	srcip[IPV4_ADDR_LEN];
	uint8_t	dsteth[ETH_ADDR_LEN];
	uint8_t	dstip[IPV4_ADDR_LEN];
} myarp_t;

typedef struct {
	uint8_t	eth_dst[ETH_ADDR_LEN];
	uint8_t	eth_src[ETH_ADDR_LEN];
	uint16_t	eth_type;
	
	uint16_t	arp_ethtype;
	uint16_t	arp_iptype;
	uint8_t	arp_ethlen;
	uint8_t	arp_iplen;
	uint16_t	arp_op;
	uint8_t	arp_srceth[ETH_ADDR_LEN];
	uint8_t	arp_srcip[IPV4_ADDR_LEN];
	uint8_t	arp_dsteth[ETH_ADDR_LEN];
	uint8_t	arp_dstip[IPV4_ADDR_LEN];

	uint8_t	padding[ARP_PADDING];
} myetharp_t;

extern void arp_request(pcap_t *fp, uint8_t *ip);
extern void arp_reply(pcap_t *fp, uint8_t *dsteth, uint8_t *dstip);
extern void arp_main(pcap_t *fp, uint8_t *pkt, int len);
extern void arp_resend(pcap_t *fp, uint8_t *eth);
extern void arp_send(pcap_t *fp, myethip_t *pkt, uint8_t *dstip, int iplen);
/***
 *** ARP cache
 ***/

extern uint8_t	*arptable_existed(uint8_t *ip);
extern void				arptable_add(uint8_t *ip, uint8_t *eth);

#endif /* __ARP_H__ */
