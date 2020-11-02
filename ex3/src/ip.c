#include "ip.h"

void
dump_ip(pcap_t *fp, uint8_t *pkt, int len)
{
	myethip_t	*ip;
	char		srcip[BUFLEN_IP];
	char		dstip[BUFLEN_IP];

	ip = (myethip_t *) pkt;

#if(FG_IP_DUMP == 1)
	printf("IP from %s to %s\n",
		ip_addrstr(ip->ip.srcip, srcip), ip_addrstr(ip->ip.dstip, dstip));
#endif /* FG_IP_DUMP */

}