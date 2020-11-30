#ifndef __IP_H__
#define __IP_H__

#include <pcap.h>

/***
 ***	IP
 ***/

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

	unsigned char	data[1];
} myip_t;

typedef struct {
	unsigned char	eth_dst[6];
	unsigned char	eth_src[6];
	unsigned short	eth_type;

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

	unsigned char	data[1480];
} myethip_t;

#define hlen(ip)			((ip)->ip_verhlen & 0x0f)
#define ver(ip)				((ip)->ip_verhlen >> 4)
#define verhlen(ver,hlen)	(((ver) << 4) + (hlen))

extern unsigned short	ip_checksum(myip_t *ip);
extern void				ip_send(pcap_t *fp, myethip_t *pkt, int ipdatalen);
extern void 			ip_main(pcap_t *fp, unsigned char *pkt_data, int pktlen);

#endif /* __IP_H__ */
