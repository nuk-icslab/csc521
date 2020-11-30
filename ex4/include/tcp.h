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
	uint16_t		tcp_srcport;
	uint16_t		tcp_dstport;
	uint32_t	tcp_seq;
	uint32_t	tcp_ack;
	uint8_t		tcp_hlen;
	uint8_t		tcp_flags;
	uint16_t		tcp_window;
	uint16_t		tcp_chksum;
	uint16_t		tcp_urgent;
	uint8_t		tcp_data[1];
} mytcp_t;

typedef struct {
	uint8_t		ip_verhlen;
	uint8_t		ip_servicetype;
	uint16_t		ip_length;

	uint16_t		ip_identification;
	uint16_t		ip_fragoff;

	uint8_t		ip_ttl;
	uint8_t		ip_protocol;
	uint16_t		ip_chksum;

	uint8_t		ip_srcip[4];
	uint8_t		ip_dstip[4];

	uint16_t		tcp_srcport;
	uint16_t		tcp_dstport;
	uint32_t	tcp_seq;
	uint32_t	tcp_ack;
	uint8_t		tcp_hlen5;
	uint8_t		tcp_flags;
	uint16_t		tcp_window;
	uint16_t		tcp_chksum;
	uint16_t		tcp_urgent;
	uint8_t		tcp_data[1460];
					/* 1500 - ip_header20 - tcp_header20 */
} myiptcp_t;

extern char		*tcp_flagstr(uint8_t flags);
extern uint16_t	tcp_checksum(myiptcp_t *tcpip, int len);

extern void		tcp_main(pcap_t *fp, myip_t *ip, int len);
extern void		tcp_send(pcap_t *fp, uint16_t srcport,
				uint32_t dstip, uint16_t dstport,
				char *data, int len);

#endif /* __TCP_H__ */
