#ifndef __IP_H__
#define __IP_H__

#include <pcap.h>

/***
 ***	IP
 ***/

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

	uint8_t	data[1];
} myip_t;

typedef struct {
	uint8_t	eth_dst[6];
	uint8_t	eth_src[6];
	uint16_t	eth_type;

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

	uint8_t	data[1480];
} myethip_t;

#define hlen(ip)			((ip)->ip_verhlen & 0x0f)
#define ver(ip)				((ip)->ip_verhlen >> 4)
#define verhlen(ver,hlen)	(((ver) << 4) + (hlen))

extern uint16_t	ip_checksum(myip_t *ip);
extern void				ip_send(pcap_t *fp, myethip_t *pkt, int ipdatalen);
extern void 			ip_main(pcap_t *fp, uint8_t *pkt_data, int pktlen);

#endif /* __IP_H__ */
