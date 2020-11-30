#ifndef __UDP_H__
#define __UDP_H__

#include "ip.h"

/***
 ***	UDP
 ***/

typedef struct {
	unsigned short	udp_srcport;
	unsigned short	udp_dstport;
	unsigned short	udp_length;
	unsigned short	udp_chksum;
	unsigned char	udp_data[1];
} myudp_t;

typedef struct {
	unsigned char	ip_verhlen;
	unsigned char	ip_servicetype;
	unsigned short	ip_length;

	unsigned short	ip_identification;
	unsigned short	ip_fragoff;

	unsigned char	ip_ttl;
	unsigned char	ip_protocol;
	unsigned short	ip_chksum;

	unsigned char	ip_srcip[4];
	unsigned char	ip_dstip[4];

	unsigned short	udp_srcport;
	unsigned short	udp_dstport;
	unsigned short	udp_length;
	unsigned short	udp_chksum;
	unsigned char	udp_data[1472]; /* 1500 - ip_header20 - udp_header8 */
} myipudp_t;


extern unsigned short	udp_checksum(myipudp_t *udpip);
extern void		udp_main(pcap_t *fp, myip_t *ip, int len);
extern void		udp_send(pcap_t *fp, unsigned short srcport,
				unsigned long dstip, unsigned short dstport,
				char *data, int len);


#endif /* __UDP_H__ */
