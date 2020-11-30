#ifndef __UDP_H__
#define __UDP_H__

#include "ip.h"

/***
 ***	UDP
 ***/

typedef struct {
	uint16_t	udp_srcport;
	uint16_t	udp_dstport;
	uint16_t	udp_length;
	uint16_t	udp_chksum;
	uint8_t	udp_data[1];
} myudp_t;

typedef struct {
	uint8_t	ip_verhlen;
	uint8_t	ip_servicetype;
	uint16_t	ip_length;

	uint16_t	ip_identification;
	uint16_t	ip_fragoff;

	uint8_t	ip_ttl;
	uint8_t	ip_protocol;
	uint16_t	ip_chksum;

	uint8_t	ip_srcip[4];
	uint8_t	ip_dstip[4];

	uint16_t	udp_srcport;
	uint16_t	udp_dstport;
	uint16_t	udp_length;
	uint16_t	udp_chksum;
	uint8_t	udp_data[1472]; /* 1500 - ip_header20 - udp_header8 */
} myipudp_t;


extern uint16_t	udp_checksum(myipudp_t *udpip);
extern void		udp_main(pcap_t *fp, myip_t *ip, int len);
extern void		udp_send(pcap_t *fp, uint16_t srcport,
				uint32_t dstip, uint16_t dstport,
				char *data, int len);


#endif /* __UDP_H__ */
