#ifndef __COMMON_H__
#define __COMMON_H__

#include <pcap/pcap.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

#define FG_NATIVE_CYGWIN	1

#define FG_ARP_SEND_REQUEST	0
#define FG_ICMP_SEND_REQUEST	1

/***
 ***	Flags
 ***/

#define DEBUG_PACKET		1
#define DEBUG_PACKET_DUMP	0
#define DEBUG_ARP			0
#define DEBUG_ARP_REQUEST	0
#define DEBUG_ARP_REPLY		0
#define DEBUG_ARP_DUMP		0

#define DEBUG_ARPCACHE		1
#define DEBUG_IP			1
#define DEBUG_ICMP			1

#define DEBUG_CHECKSUM		1

#define MAX_CAP_LEN			1514
#define MAX_DUMP_PKT		5

#define BUFLEN_ETH			18
#define BUFLEN_IP			16
#define MAX_DUMP_LEN		80
#define MAX_LINE_LEN		16
#define MAX_LINEBUF			256

/***
 ***	Assigned Numbers and Prameters
 ***/
 
#define ETH_IP		0x0008
#define ETH_ARP		0x0608

#define ETH_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

typedef struct {
	uint8_t	eth_dst[ETH_ADDR_LEN];
	uint8_t	eth_src[ETH_ADDR_LEN];
	uint16_t	eth_type;
	uint8_t	data[MAX_CAP_LEN-14];
} myeth_t;

#define COPY_ETH_ADDR(dst, src)	(memcpy((dst), (src), ETH_ADDR_LEN))
#define COPY_IPV4_ADDR(dst, src)	(memcpy((dst), (src), IPV4_ADDR_LEN))

typedef uint32_t	ipaddr_t;

/******
 ****** from config.c
 ******/

extern uint8_t	myethaddr[ETH_ADDR_LEN];
extern uint8_t	myipaddr[IPV4_ADDR_LEN];
extern uint8_t	myrouterip[IPV4_ADDR_LEN];
extern uint8_t	mynetmask[IPV4_ADDR_LEN];

extern uint8_t	defarpip[IPV4_ADDR_LEN];
extern uint8_t	defpingip[IPV4_ADDR_LEN];

#define getip(ipaddr)	(*((ipaddr_t *)(ipaddr)))
#define setip(dip, sip)	(*((ipaddr_t *) (dip)) = *((ipaddr_t *) (sip)))
#define ismyip(ipaddr)	((getip(ipaddr)) == getip(myipaddr))

#define getnetid(ip)	((*((ipaddr_t *)(ip))) & (*((ipaddr_t *) mynetmask)))
#define ismynet(ip)		((getnetid(ip)) == getnetid(myipaddr))

/******
 ******	utilities
 ******/

extern void			pkt_main(pcap_t *fp, struct pcap_pkthdr	*header, uint8_t *pkt_data);

extern int			readready();
extern char			*time2decstr(time_t t);
extern ipaddr_t		my_inet_addr(char *ip);
extern char			*ip_addrstr(uint8_t *ip, char *buf);
extern char			*eth_macaddr(const uint8_t *a, char *buf);

extern void			print_ip(uint8_t *ip, char *msg);
extern void			print_data(const uint8_t *data, int len);

extern uint16_t	swap16(uint16_t s);
extern uint32_t	swap32(uint32_t val);
extern uint16_t	checksum(char *ptr, int len);

#endif /* __COMMON_H__ */
