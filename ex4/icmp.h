#ifndef __ICMP_H__
#define __ICMP_H__

#include <pcap.h>
#include "ip.h"

#define ICMP_PADDING	18

/***
 ***	ICMP
 ***/

typedef struct {
	unsigned char	icmp_type;
	unsigned char	icmp_code;
	unsigned short	icmp_chksum;
	unsigned short	icmp_id;
	unsigned short	icmp_seq;
	char		icmp_data[1];
} myicmp_t;

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

	unsigned char	icmp_type;
	unsigned char	icmp_code;
	unsigned short	icmp_chksum;
	unsigned short	icmp_id;
	unsigned short	icmp_seq;
	char		padding[ICMP_PADDING];
} myethicmp_t;

extern void icmp_main(pcap_t *fp, myip_t *ip, int len);
extern void icmp_ping(pcap_t *fp, myethip_t *pkt, unsigned char *dstip);

#endif /* __ICMP_H__ */
