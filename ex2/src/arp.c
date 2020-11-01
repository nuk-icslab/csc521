#include <stdio.h>
#include <string.h>
#include "common.h"
#include "arp.h"

/*
 * arp_request() - send a ARP request for <IP> address
 */

void
arp_request(pcap_t *fp, uint8_t *ip)
{
	myetharp_t		pkt;
	
	if(ip == NULL) ip = defarpip;
	COPY_ETH_ADDR(pkt.eth_dst, eth_broadcast_addr);
	COPY_ETH_ADDR(pkt.eth_src, myethaddr);
	pkt.eth_type = ETH_ARP;

	pkt.arp.ethtype = ARP_ETH_TYPE;
	pkt.arp.iptype = ETH_IP;
	pkt.arp.ethlen = ETH_ADDR_LEN;
	pkt.arp.iplen = IPV4_ADDR_LEN;
	pkt.arp.op = ARP_OP_REQUEST;
	COPY_ETH_ADDR(pkt.arp.srceth, myethaddr);
	COPY_IPV4_ADDR(pkt.arp.srcip, myipaddr);
	COPY_ETH_ADDR(pkt.arp.dsteth, eth_null_addr);
	COPY_IPV4_ADDR(pkt.arp.dstip, ip);
	memset(pkt.padding, 0, ARP_PADDING);
	
	if(pcap_sendpacket(fp, (uint8_t *) &pkt, sizeof(pkt)) != 0) {
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
arp_reply(pcap_t *fp, uint8_t *dsteth, uint8_t *dstip)
{
	myetharp_t		pkt;

	COPY_ETH_ADDR(pkt.eth_dst, dsteth);
	COPY_ETH_ADDR(pkt.eth_src, myethaddr);
	pkt.eth_type = ETH_ARP;

	pkt.arp.ethtype = ARP_ETH_TYPE;
	pkt.arp.iptype = ETH_IP;
	pkt.arp.ethlen = ETH_ADDR_LEN;
	pkt.arp.iplen = IPV4_ADDR_LEN;
	pkt.arp.op = ARP_OP_REPLY;
	COPY_ETH_ADDR(pkt.arp.srceth, myethaddr);
	COPY_IPV4_ADDR(pkt.arp.srcip, myipaddr);
	COPY_ETH_ADDR(pkt.arp.dsteth, dsteth);
	COPY_IPV4_ADDR(pkt.arp.dstip, dstip);
	memset(pkt.padding, 0, ARP_PADDING);
	
	if(pcap_sendpacket(fp, (uint8_t *) &pkt, sizeof(pkt)) != 0) {
        	fprintf(stderr,"\nError sending: %s\n", pcap_geterr(fp));
	}
#if(DEBUG_ARP_REPLY == 1)
	printf("arp_reply() to %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ARP_REPLY */
}

void
arp_main(pcap_t *fp, uint8_t *pkt, int len)
{
	myetharp_t	*arp;
	char		srceth[BUFLEN_ETH], srcip[BUFLEN_IP];
	char		dsteth[BUFLEN_ETH], dstip[BUFLEN_IP];

	arp = (myetharp_t *) pkt;

#if(DEBUG_ARP == 1)
	printf("ARP Eth=%04x/%d, IP=%04x/%d, Op=%04x\n"
		"\tFrom %s (%s)\n"
		"\tTo   %s (%s)\n",
		(int) arp->arp.ethtype, (int) arp->arp.ethlen,
		(int) arp->arp.iptype,  (int) arp->arp.iplen,
		(int) arp->arp.op,
		eth_macaddr(arp->arp.srceth, srceth), ip_addrstr(arp->arp.srcip, srcip),
		eth_macaddr(arp->arp.dsteth, dsteth), ip_addrstr(arp->arp.dstip, dstip));
#endif /* DEBUG_ARP */

	/* ARP request to My IP: reply it */
	switch(arp->arp.op) {
	case ARP_OP_REQUEST: /* ARP Request */
		if(memcmp(arp->arp.dstip, myipaddr, IPV4_ADDR_LEN) == 0)
			arp_reply(fp, arp->arp.srceth, arp->arp.srcip);
		break;

	case ARP_OP_REPLY: /* ARP Reply */
		break;

#if(DEBUG_ARP == 1)
	default:
		printf("unknown ARP opcode\n");
#endif /* DEBUG_ARP */
	}
}
