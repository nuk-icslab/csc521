#ifndef __IP_H__
#define __IP_H__

#include <pcap/pcap.h>
#include "common.h"

typedef struct {
	uint8_t	bypass[12];
	uint8_t	srcip[4];
	uint8_t	dstip[4];
	uint8_t	skip[1];
} myip_t;

typedef struct {
	uint8_t	dst[6];
	uint8_t	src[6];
	uint16_t	type;

  myip_t ip;

} myethip_t;

extern void dump_ip(pcap_t*, uint8_t*, int);

#endif /* __IP_H__ */