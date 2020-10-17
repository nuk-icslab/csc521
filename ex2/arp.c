#include <stdio.h>
#include <string.h>
#include "common.h"
#include "arp.h"

unsigned char	ethbroadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char	ethnull[] = {0, 0, 0, 0, 0, 0};

/*
 * arp_request() - send a ARP request for <IP> address
 */

void
arp_request(pcap_t *fp, unsigned char *ip)
{
	myetharp_t		pkt;
	
	if(ip == NULL) ip = defarpip;
	memcpy(pkt.eth_dst, ethbroadcast, 6);
	memcpy(pkt.eth_src, myethaddr, 6);
	pkt.eth_type = ETH_ARP;

	pkt.arp_ethtype = 0x0100;
	pkt.arp_iptype = ETH_IP;
	pkt.arp_ethlen = 6;
	pkt.arp_iplen = 4;
	pkt.arp_op = 0x0100;
	memcpy(pkt.arp_srceth, myethaddr, 6);
	memcpy(pkt.arp_srcip, myipaddr, 4);
	memcpy(pkt.arp_dsteth, ethnull, 6);	
	memcpy(pkt.arp_dstip, ip, 4);
	memset(pkt.padding, 0, ARP_PADDING);
	
	if(pcap_sendpacket(fp, (unsigned char *) &pkt, sizeof(pkt)) != 0) {
        	fprintf(stderr,"\nError sending: %s\n", pcap_geterr(fp));
	}
#if(DEBUG_ARP_REQUEST == 1)
	printf("arp_request() to %s\n", ip_addrstr(ip, NULL));
#endif /* DEBUG_ARP_REQUEST */
}

/*
 * arp_reply() - reply MY hardware address
 */

void
arp_reply(pcap_t *fp, unsigned char *dsteth, unsigned char *dstip)
{
	myetharp_t		pkt;

	memcpy(pkt.eth_dst, dsteth, 6);
	memcpy(pkt.eth_src, myethaddr, 6);
	pkt.eth_type = ETH_ARP;

	pkt.arp_ethtype = 0x0100;
	pkt.arp_iptype = ETH_IP;
	pkt.arp_ethlen = 6;
	pkt.arp_iplen = 4;
	pkt.arp_op = 0x0200;
	memcpy(pkt.arp_srceth, myethaddr, 6);
	memcpy(pkt.arp_srcip, myipaddr, 4);
	memcpy(pkt.arp_dsteth, dsteth, 6);
	memcpy(pkt.arp_dstip, dstip, 4);
	memset(pkt.padding, 0, 18);
	
	if(pcap_sendpacket(fp, (unsigned char *) &pkt, sizeof(pkt)) != 0) {
        	fprintf(stderr,"\nError sending: %s\n", pcap_geterr(fp));
	}
#if(DEBUG_ARP_REPLY == 1)
	printf("arp_reply() to %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ARP_REPLY */
}

void
arp_main(pcap_t *fp, unsigned char *pkt, int len)
{
	myetharp_t	*arp;
	char		srceth[BUFLEN_ETH], srcip[BUFLEN_IP];
	char		dsteth[BUFLEN_ETH], dstip[BUFLEN_IP];

	arp = (myetharp_t *) pkt;

#if(DEBUG_ARP == 1)
	printf("ARP Eth=%04x/%d, IP=%04x/%d, Op=%04x\n"
		"\tFrom %s (%s)\n"
		"\tTo   %s (%s)\n",
		(int) arp->arp_ethtype, (int) arp->arp_ethlen,
		(int) arp->arp_iptype,  (int) arp->arp_iplen,
		(int) arp->arp_op,
		eth_macaddr(arp->arp_srceth, srceth), ip_addrstr(arp->arp_srcip, srcip),
		eth_macaddr(arp->arp_dsteth, dsteth), ip_addrstr(arp->arp_dstip, dstip));
#endif /* DEBUG_ARP */

	/* ARP request to My IP: reply it */
	switch(arp->arp_op) {
	case 0x0100: /* ARP Request */
		if(memcmp(arp->arp_dstip, myipaddr, 4) == 0)
			arp_reply(fp, arp->arp_srceth, arp->arp_srcip);
		break;

	case 0x0200: /* ARP Reply */
		break;

#if(DEBUG_ARP == 1)
	default:
		printf("unknown ARP opcode\n");
#endif /* DEBUG_ARP */
	}
}
