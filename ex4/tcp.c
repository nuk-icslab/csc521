#include <stdio.h>
#include <string.h>

#include "common.h"
#include "tcp.h"

/******
 ******
 ******/

char *
tcp_flagstr(unsigned char flags)
{
	static char	buf[7];

	buf[0] = ((flags & TCP_FG_URT) != 0) ? 'U' : '-';
	buf[1] = ((flags & TCP_FG_ACK) != 0) ? 'A' : '-';
	buf[2] = ((flags & TCP_FG_PSH) != 0) ? 'P' : '-';
	buf[3] = ((flags & TCP_FG_RST) != 0) ? 'R' : '-';
	buf[4] = ((flags & TCP_FG_SYN) != 0) ? 'S' : '-';
	buf[5] = ((flags & TCP_FG_FIN) != 0) ? 'F' : '-';
	buf[6] = '\0';
	return buf;
}

unsigned short
tcp_checksum(myiptcp_t *tcpip, int len)
{
	unsigned short	oldchksum, newchksum;
	unsigned short	*srcip2, *dstip2;
	unsigned long	sum;
	int				tcplen;

	tcplen = (len > 0) ? len : (swap16(tcpip->ip_length) - hlen(tcpip) * 4);
	/* checksum: pseudo header */
	srcip2 = (unsigned short *) tcpip->ip_srcip;
	dstip2 = (unsigned short *) tcpip->ip_dstip;
	sum = swap16(*srcip2) + swap16(*(srcip2 + 1))
		+ swap16(*dstip2) + swap16(*(dstip2 + 1)) + 6 + tcplen;
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	/* checksum: tcp packet */
	oldchksum = tcpip->tcp_chksum;
	tcpip->tcp_chksum = swap16((unsigned short) sum);
	newchksum = checksum((char*) &tcpip->tcp_srcport, tcplen);
	tcpip->tcp_chksum = oldchksum;

	/* final */
	return newchksum;
}

void
tcp_main(pcap_t *fp, myip_t *ip, int len)
{
#if(DEBUG_TCP == 1)
	unsigned short int	chk = tcp_checksum((myiptcp_t *) ip);
	mytcp_t				*tcp = (mytcp_t *) ip->data;
	int					tcplen = len - hlen(ip) * 4;
	unsigned short int	srcport, dstport;

	srcport = swap16(tcp->tcp_srcport);
	dstport = swap16(tcp->tcp_dstport);

	printf("TCP %s: %d->%d, Len=%d, chksum=%04x/%04x\n",  tcp_flagstr(tcp->tcp_flags),
		srcport, dstport, tcplen, (int) tcp->tcp_chksum, chk);
#endif /* DEBUG_TCP == 1 || DEBUG_CHECKSUM == 1 */
#if(DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_TCP_DUMP == 1)
		print_data((unsigned char *)ip, len);
#endif /* DEBUG_TCP_DUMP */
}

void
tcp_send(pcap_t *fp, unsigned short srcport, unsigned long dstip,
		unsigned short dstport, char *data, int len)
{
	myethip_t	pktbuf, *pkt;
	myiptcp_t	*tcp;
	
	pkt = &pktbuf;
	pkt->ip_protocol = 0x06; /* TCP */
	setip(pkt->ip_dstip, &dstip);
	setip(pkt->ip_srcip, myipaddr);

	tcp = (myiptcp_t *)(((myeth_t *) pkt)->data);
	tcp->tcp_srcport = swap16(srcport);
	tcp->tcp_dstport = swap16(dstport);
	memcpy(tcp->tcp_data, data, len);
	tcp->tcp_chksum = tcp_checksum(tcp, len + 20);
	ip_send(fp, pkt, len + 20);
}
