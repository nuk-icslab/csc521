#include <stdio.h>
#include "common.h"
#include "arp.h"
#include <string.h>

uint8_t	ethbroadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t	ethnull[] = {0, 0, 0, 0, 0, 0};

/*
 * Tosend Queue with 1 Buffer (Pending for ARP)
 */
 
myethip_t	tosend_packet;
int			tosend_len = 0;
ipaddr_t	tosend_ip = 0;

/*
 * arp_request() - send a ARP request for <IP> address
 */

void
arp_request(pcap_t *fp, uint8_t *ip)
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
	setip(pkt.arp_srcip, myipaddr);
	memcpy(pkt.arp_dsteth, ethnull, 6);	
	setip(pkt.arp_dstip, ip);
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

	memcpy(pkt.eth_dst, dsteth, 6);
	memcpy(pkt.eth_src, myethaddr, 6);
	pkt.eth_type = ETH_ARP;

	pkt.arp_ethtype = 0x0100;
	pkt.arp_iptype = ETH_IP;
	pkt.arp_ethlen = 6;
	pkt.arp_iplen = 4;
	pkt.arp_op = 0x0200;
	memcpy(pkt.arp_srceth, myethaddr, 6);
	setip(pkt.arp_srcip, myipaddr);
	memcpy(pkt.arp_dsteth, dsteth, 6);
	setip(pkt.arp_dstip, dstip);
	memset(pkt.padding, 0, 18);
	
	if(pcap_sendpacket(fp, (uint8_t *) &pkt, sizeof(pkt)) != 0) {
        	fprintf(stderr,"\nError sending: %s\n", pcap_geterr(fp));
	}
#if(DEBUG_ARP_REPLY == 1)
	printf("arp_reply() to %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ARP_REPLY */
}

/*
 * arp_main() - prpocessing a receiving ARP packet
 */
 
void
arp_main(pcap_t *fp, uint8_t *pkt, int len)
{
	myetharp_t		*arp;
	uint8_t	*ethaddr;
#if(DEBUG_ARP == 1)	
	char			srceth[BUFLEN_ETH], srcip[BUFLEN_IP];
	char			dsteth[BUFLEN_ETH], dstip[BUFLEN_IP];
#endif /* DEBUG_ARP */
	
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
#if(DEBUG_PACKET_DUMP == 0 && DEBUG_ARP_DUMP == 1)
		print_data(pkt, len);
#endif /* DEBUG_ARP_DUMP */
	/* ARP request to My IP: reply it */
	switch(arp->arp_op) {
	case 0x0100: /* ARP Request */
		if(ismyip(arp->arp_dstip))
			arp_reply(fp, arp->arp_srceth, arp->arp_srcip);
		break;

	case 0x0200: /* ARP Reply */
		if(ismyip(arp->arp_dstip))
			arptable_add(arp->arp_srcip, arp->arp_srceth);
		if(tosend_len > 0) {
			if((ethaddr = arptable_existed((uint8_t *) &tosend_ip)) != NULL)
		   		arp_resend(fp, ethaddr);
			else
				arp_request(fp, (uint8_t *) &tosend_ip);
		}
		break;

#if(DEBUG_ARP == 1)
	default:
		printf("unknown ARP opcode\n");
#endif /* DEBUG_ARP */
	}
}

/*
 * arp_resend() - send out the queued packet to the obtained MAC
 */


void
arp_resend(pcap_t *fp, uint8_t *eth)
{
	myethip_t	*pkt = &tosend_packet;

	memcpy(pkt->eth_dst, eth, 6);
	if(pcap_sendpacket(fp, (uint8_t *) pkt, tosend_len) != 0) {
		fprintf(stderr,"\nError sending: %s\n", pcap_geterr(fp));
	}
	tosend_len = 0;
	tosend_ip = 0;
}

/*
 * arp_send()
 */

void
arp_send(pcap_t *fp, myethip_t *pkt, uint8_t *dstip, int iplen)
{
	uint8_t	*eth;
	int				len;

	len = iplen + 14;
	memcpy(pkt->eth_src, myethaddr, 6);
	if((eth = arptable_existed(dstip)) != NULL) {
		/* Send directly if MAC available */
		memcpy(pkt->eth_dst, eth, 6);
		if(pcap_sendpacket(fp, (uint8_t *) pkt, len) != 0) {
        		fprintf(stderr,"\nError sending: %s\n", pcap_geterr(fp));
		}
	} else {
		/* Put to the queue and reqeust ARP if MAC unavilable */
		tosend_ip = *((ipaddr_t *) dstip);
		tosend_len = len;
		memcpy((uint8_t *) &tosend_packet, pkt, len);
		arp_request(fp, (uint8_t *) &tosend_ip);
	}
}


