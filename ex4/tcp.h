#ifndef __TCP_H__
#define __TCP_H__

#include "ip.h"

/***
 ***	TCP
 ***/

#define TCP_FG_URT		0x20
#define TCP_FG_ACK		0x10
#define TCP_FG_PSH		0x08
#define TCP_FG_RST		0x04
#define TCP_FG_SYN		0x02
#define TCP_FG_FIN		0x01

#define tcphlen(tcp)		(((tcp)->tcp_hlen >> 4) << 2)
#define tcphlen_set(tcp,n)	((tcp)->tcp_hlen = (((n) >> 2) << 4))
#define tcpflag(tcp,flag)	(((tcp)->tcp_flags & (flag)) != 0)
#define tcpflag_set(tcp,flag)	((tcp)->tcp_flags |= (flag))

typedef struct {
	unsigned short		tcp_srcport;
	unsigned short		tcp_dstport;
	unsigned long int	tcp_seq;
	unsigned long int	tcp_ack;
	unsigned char		tcp_hlen;
	unsigned char		tcp_flags;
	unsigned short		tcp_window;
	unsigned short		tcp_chksum;
	unsigned short		tcp_urgent;
	unsigned char		tcp_data[1];
} mytcp_t;

typedef struct {
	unsigned char		ip_verhlen;
	unsigned char		ip_servicetype;
	unsigned short		ip_length;

	unsigned short		ip_identification;
	unsigned short		ip_fragoff;

	unsigned char		ip_ttl;
	unsigned char		ip_protocol;
	unsigned short		ip_chksum;

	unsigned char		ip_srcip[4];
	unsigned char		ip_dstip[4];

	unsigned short		tcp_srcport;
	unsigned short		tcp_dstport;
	unsigned long int	tcp_seq;
	unsigned long int	tcp_ack;
	unsigned char		tcp_hlen5;
	unsigned char		tcp_flags;
	unsigned short		tcp_window;
	unsigned short		tcp_chksum;
	unsigned short		tcp_urgent;
	unsigned char		tcp_data[1460];
					/* 1500 - ip_header20 - tcp_header20 */
} myiptcp_t;

extern char		*tcp_flagstr(unsigned char flags);
extern unsigned short	tcp_checksum(myiptcp_t *tcpip, int len);

extern void		tcp_main(pcap_t *fp, myip_t *ip, int len);
extern void		tcp_send(pcap_t *fp, unsigned short srcport,
				unsigned long dstip, unsigned short dstport,
				char *data, int len);

#endif /* __TCP_H__ */
