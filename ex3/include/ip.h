#ifndef __IP_H__
#define __IP_H__

#include <pcap/pcap.h>
#include <stdio.h>
#include "common.h"

typedef struct {
	unsigned char	dst[6];
	unsigned char	src[6];
	unsigned short	type;
	unsigned char	data[1];
} myeth_t;

typedef struct {
	unsigned char	bypass[12];
	unsigned char	srcip[4];
	unsigned char	dstip[4];
	unsigned char	skip[1];
} myip_t;

typedef struct {
	unsigned char	dst[6];
	unsigned char	src[6];
	unsigned short	type;

	unsigned char	bypass[12];
	unsigned char	srcip[4];
	unsigned char	dstip[4];
	unsigned char	skip[1];
} myethip_t;

extern void dump_ip(pcap_t*, uint8_t*, int);

#endif /* __IP_H__ */