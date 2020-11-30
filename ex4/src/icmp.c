#include <stdio.h>
#include <string.h>

#include "common.h"
#include "icmp.h"

char	*ICMP_TYPE[] = {
		"Echo Reply",
		"1", "2",
		"Destination Unreachable",
		"Source Quench",
		"Redirect (Change a Route)",
		"6", "7",
		"Echo Request",
		"9", "10",
		"Time Exceeded for a Datagram",
		"Parameter Problem on a Datagram",
		"Timestamp Request",
		"Timestamp Reply",
		"Information Request",
		"Information Reply",
		"Address Mask Request",
		"Address Mask Reply"
};
#define N_ICMP_TYPE	(sizeof(ICMP_TYPE)/sizeof(char*))

char	*ICMP_CODE[] = {
		"Network Unreachable",
		"Host Unreachable",
		"Protocol Unreachable",
		"Port Unreachable",
		"Fragmentation Needed and DF Set",
		"Source Route Failed",
		"Destination Network Unknown",
		"Destination Host Unknown",
		"Source Host Isolated",
		"Communication with Destination Network Administratively Prohibited",
		"Communication with Destination Host Administratively Prohibited",
		"Network Unreachable for Type of Service",
		"Host Unreachable for Type of Service"
};
#define N_ICMP_CODE	(sizeof(ICMP_CODE)/sizeof(char*))

/******
 ******
 ******/

void
icmp_main(pcap_t *fp, myip_t *ip, int len)
{
	myicmp_t	*icmp = (myicmp_t *) ip->data;
	int		icmplen = len - hlen(ip) * 4;

#if(DEBUG_ICMP == 1)
	printf("%4d ICMP ", icmplen);
#endif /* DEBUG_ICMP == 1 */

	print_ip(ip->ip_srcip, "->");
	print_ip(ip->ip_dstip, ": ");

	if(icmp->icmp_type >= N_ICMP_TYPE) {
		printf("[Bad Type %d] ", icmp->icmp_type);
	} else
		printf("[%s] ", ICMP_TYPE[icmp->icmp_type]);

	switch(icmp->icmp_type) {
	case 0x00: case 0x08:
		printf("\n");
		print_data((uint8_t *) icmp, icmplen);
		break;
	case 0x03: case 0x05: case 0x0b:
	default:
		if(icmp->icmp_code >= N_ICMP_CODE)
			printf("Bad Code(%02x)\n", (int)icmp->icmp_code);
		else
			printf("%s\n", ICMP_CODE[icmp->icmp_code]);
	}
}


void
icmp_ping(pcap_t *fp, myethip_t *pkt, uint8_t *dstip)
{
	myethicmp_t	pktbuf;
	myicmp_t	*icmp;
	int			len;

	if(pkt == NULL) pkt = (myethip_t *) &pktbuf;
	icmp = (myicmp_t *) pkt->data;
	if(dstip == NULL) dstip = defpingip;

#if(DEBUG_ICMP == 1)
	printf("Ping %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ICMP */
	setip(pkt->ip_dstip, dstip);
	pkt->ip_protocol = 0x01; /* ICMP */
	icmp->icmp_type   = 8; /* Echo Request */
	icmp->icmp_code   = 0;
	icmp->icmp_chksum = 0x0000;
	icmp->icmp_id     = 0x0123;	/* usually PID (process ID) */
	icmp->icmp_seq    = 0x0000;
	memset(icmp->icmp_data, 0, ICMP_PADDING);
	len = 8 + ICMP_PADDING;
	icmp->icmp_chksum = checksum((char *) icmp, len);
	ip_send(fp, pkt, len);
}
