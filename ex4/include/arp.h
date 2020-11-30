#ifndef __ARP_H__
#define __ARP_H__

#include <pcap/pcap.h>
#include "ip.h"

#define ARP_PADDING	18

/***
 *** ARP
 ***/

typedef struct {
	uint16_t	arp_ethtype;
	uint16_t	arp_iptype;
	uint8_t	arp_ethlen;
	uint8_t	arp_iplen;
	uint16_t	arp_op;
	uint8_t	arp_srceth[6];
	uint8_t	arp_srcip[4];
	uint8_t	arp_dsteth[6];
	uint8_t	arp_dstip[4];
} myarp_t;

typedef struct {
	uint8_t	eth_dst[6];
	uint8_t	eth_src[6];
	uint16_t	eth_type;

	uint16_t	arp_ethtype;
	uint16_t	arp_iptype;
	uint8_t	arp_ethlen;
	uint8_t	arp_iplen;
	uint16_t	arp_op;
	uint8_t	arp_srceth[6];
	uint8_t	arp_srcip[4];
	uint8_t	arp_dsteth[6];
	uint8_t	arp_dstip[4];
	uint8_t	padding[ARP_PADDING];
} myetharp_t;

extern void	arp_request(pcap_t *fp, uint8_t *ip);
extern void	arp_reply(pcap_t *fp, uint8_t *dsteth, uint8_t *dstip);
extern void	arp_main(pcap_t *fp, uint8_t *pkt, int len);

extern void	arp_send(pcap_t *fp, myethip_t *pkt, uint8_t *dstip, int len);
extern void arp_resend(pcap_t *fp, uint8_t *eth);

/***
 *** ARP cache
 ***/

extern uint8_t	*arptable_existed(uint8_t *ip);
extern void				arptable_add(uint8_t *ip, uint8_t *eth);

#endif /* __ARP_H__ */
