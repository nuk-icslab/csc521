#ifndef __ICMP_H__
#define __ICMP_H__

#include <pcap/pcap.h>
#include "ip.h"

#define ICMP_PADDING	18

/***
 ***	ICMP
 ***/

typedef struct {
	uint8_t	icmp_type;
	uint8_t	icmp_code;
	uint16_t	icmp_chksum;
	uint16_t	icmp_id;
	uint16_t	icmp_seq;
	char		icmp_data[1];
} myicmp_t;

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

	uint8_t	icmp_type;
	uint8_t	icmp_code;
	uint16_t	icmp_chksum;
	uint16_t	icmp_id;
	uint16_t	icmp_seq;
	char		padding[ICMP_PADDING];
} myethicmp_t;

extern void icmp_main(pcap_t *fp, myip_t *ip, int len);
extern void icmp_ping(pcap_t *fp, myethip_t *pkt, uint8_t *dstip);

#endif /* __ICMP_H__ */
