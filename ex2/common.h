#ifndef __COMMON_H__
#define __COMMON_H__

#include <pcap/pcap.h>
#include <time.h>
#include <errno.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

#define FG_NATIVE_CYGWIN	1

#define FG_ARP_SEND_REQUEST	1

/***
 ***	Flags
 ***/

#define DEBUG_PACKET		1
#define DEBUG_PACKET_DUMP	0
#define DEBUG_ARP			1
#define DEBUG_ARP_REQUEST	1
#define DEBUG_ARP_REPLY		1
#define DEBUG_ARP_DUMP		1

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

typedef struct {
	unsigned char	eth_dst[6];
	unsigned char	eth_src[6];
	unsigned short	eth_type;
	unsigned char	data[1];
} myeth_t;

typedef unsigned long int	ipaddr_t;

/******
 ******
 ******/

extern unsigned char	myethaddr[6];
extern unsigned char	myipaddr[4];
extern unsigned char	defarpip[4];

#define getip(ipaddr)	(*((ipaddr_t *)(ipaddr)))
#define ismyip(ipaddr)	((getip(ipaddr)) == getip(myipaddr))

/******
 ******	utilities
 ******/

extern int			readready();
extern char			*time2decstr(time_t t);
extern ipaddr_t		my_inet_addr(char *ip);
extern char			*ip_addrstr(unsigned char *ip, char *buf);
extern char			*eth_macaddr(const unsigned char *a, char *buf);

extern void			print_ip(unsigned char *ip, char *msg);
extern void			print_data(const unsigned char *data, int len);

#endif /* __COMMON_H__ */
