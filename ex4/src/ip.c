#include <stdio.h>
#include <string.h>

#include "common.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

/******
 ****** IP Utilities
 ******/

uint16_t
ip_checksum(myip_t *ip)
{
	uint16_t	oldchksum, newchksum;

	oldchksum = ip->ip_chksum;
	ip->ip_chksum = 0;
	newchksum = checksum((char*) ip, hlen(ip)*4);
	ip->ip_chksum = oldchksum;
	return newchksum;
}

/*
 *
 */

void
ip_main(pcap_t *fp, uint8_t *pkt, int len)
{
	myeth_t		*eth = (myeth_t *) pkt;
	myip_t		*ip = (myip_t *) eth->data;;
	int			n = swap16(ip->ip_length);

	char		srcip[BUFLEN_IP];
	char		dstip[BUFLEN_IP];

#if(DEBUG_CHECKSUM == 1)
	uint16_t	chk = ip_checksum(ip);;
#else
	uint16_t chk = 0;
#endif /* DEBUG_CHECKSUM */

#if(DEBUG_IP >= 1 || DEBUG_CHECKSUM == 1)
	printf("IP from %s to %s: Proto=%d, Len=%d, chksum=%04x/%04x\n",
		ip_addrstr(ip->ip_srcip, srcip), ip_addrstr(ip->ip_dstip, dstip),
		(int) ip->ip_protocol, n, (int) chk, (int) ip->ip_chksum);
#endif /* DEBUG_IP == 1 || DEBUG_CHECKSUM == 1 */
#if(DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 1)
		print_data(pkt, len);
#endif /* DEBUG_IP_DUMP */
	switch(ip->ip_protocol) {
	case 0x01: /* ICMP */
		icmp_main(fp, ip, n);
		break;
	case 0x06: /* TCP */
		tcp_main(fp, ip, n);
		break;
	case 0x11: /* UDP */
		udp_main(fp, ip, n);
		break;
#if(DEBUG_IP == 2)
	default:
		printf("Unsupported IP protocol: %d\n", (int) ip->ip_protocol);
#endif /* DEBUG_IP == 1 */
	}
}

/*
 * ip_send()
 */

void
ip_send(pcap_t *fp, myethip_t *pkt, int ipdatalen)
{
	int		iplen = ipdatalen + 20;
	myeth_t	*eth = (myeth_t *) pkt;
	uint8_t	*dstip;

	pkt->eth_type = ETH_IP;
	pkt->ip_verhlen = verhlen(4, 5);
	pkt->ip_servicetype = 0;
	pkt->ip_length = swap16((uint16_t) iplen);
	pkt->ip_identification = pkt->ip_fragoff = 0;
	if(pkt->ip_ttl == 0) pkt->ip_ttl = 255;
	pkt->ip_chksum = 0;
	setip(pkt->ip_srcip, myipaddr);
	pkt->ip_chksum = ip_checksum((myip_t *) eth->data);
	dstip = ismynet(pkt->ip_dstip) ? pkt->ip_dstip : myrouterip;
	arp_send(fp, pkt, dstip, iplen);
#if(DEBUG_IP == 1)
	printf("ip_send (dstip=%s, proto=%d, iplen=%d) to ",
				ip_addrstr(pkt->ip_dstip, NULL),
				pkt->ip_protocol, iplen);
	print_ip(dstip, "\n");
#endif /* DEBUG_IP == 1 */
}
