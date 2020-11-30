#ifndef __ARP_H__
#define __ARP_H__

#include <pcap.h>
#include "ip.h"

#define ARP_PADDING	18

/***
 *** ARP
 ***/

typedef struct {
	unsigned short	arp_ethtype;
	unsigned short	arp_iptype;
	unsigned char	arp_ethlen;
	unsigned char	arp_iplen;
	unsigned short	arp_op;
	unsigned char	arp_srceth[6];
	unsigned char	arp_srcip[4];
	unsigned char	arp_dsteth[6];
	unsigned char	arp_dstip[4];
} myarp_t;

typedef struct {
	unsigned char	eth_dst[6];
	unsigned char	eth_src[6];
	unsigned short	eth_type;

	unsigned short	arp_ethtype;
	unsigned short	arp_iptype;
	unsigned char	arp_ethlen;
	unsigned char	arp_iplen;
	unsigned short	arp_op;
	unsigned char	arp_srceth[6];
	unsigned char	arp_srcip[4];
	unsigned char	arp_dsteth[6];
	unsigned char	arp_dstip[4];
	unsigned char	padding[ARP_PADDING];
} myetharp_t;

extern void	arp_request(pcap_t *fp, unsigned char *ip);
extern void	arp_reply(pcap_t *fp, unsigned char *dsteth, unsigned char *dstip);
extern void	arp_main(pcap_t *fp, unsigned char *pkt, int len);

extern void	arp_send(pcap_t *fp, myethip_t *pkt, unsigned char *dstip, int len);
extern void arp_resend(pcap_t *fp, unsigned char *eth);

/***
 *** ARP cache
 ***/

extern unsigned char	*arptable_existed(unsigned char *ip);
extern void				arptable_add(unsigned char *ip, unsigned char *eth);

#endif /* __ARP_H__ */
