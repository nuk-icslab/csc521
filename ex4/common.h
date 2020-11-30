#ifndef __COMMON_H__
#define __COMMON_H__

#include <pcap.h>
#include <time.h>
#include <errno.h>

#define FG_NATIVE_CYGWIN	0

#define FG_ARP_SEND_REQUEST	0
#define FG_ICMP_SEND_REQUEST	0
#define FG_DNS_DO_PING		1

/***
 ***	Flags
 ***/

#define DEBUG_PACKET		0
#define DEBUG_PACKET_DUMP	0

#define DEBUG_ARP		0
#define DEBUG_ARP_REQUEST	1
#define DEBUG_ARP_REPLY		1
#define DEBUG_ARP_DUMP		0
#define DEBUG_ARPCACHE		1

#define DEBUG_CHECKSUM		0

#define DEBUG_IP		1
#define DEBUG_IP_DUMP		0

#define DEBUG_ICMP		1

#define DEBUG_UDP		1
#define DEBUG_UDP_DUMP		0

#define DEBUG_DNS		1
#define DEBUG_DNS_DUMP		1

#define DEBUG_TCP		0
#define DEBUG_TCP_DUMP		0

#define MAX_CAP_LEN		1514
#define MAX_DUMP_PKT		5

#define BUFLEN_ETH		18
#define BUFLEN_IP		16
#define MAX_DUMP_LEN		80
#define MAX_LINE_LEN		16
#define MAX_LINEBUF		256

#define MAX_DNS_TRY		3
#define DEF_DNS_SLEEP		2	/* seconds */
#define DEF_DNS_UDP_SRCPORT	0x3456
#define DEF_DNS_ID		0x5501

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
extern unsigned char	myrouterip[4];
extern unsigned char	mynetmask[4];

extern unsigned char	defarpip[4];
extern unsigned char	defpingip[4];

#define getip(ipaddr)	(*((ipaddr_t *)(ipaddr)))
#define setip(dip, sip)	(*((ipaddr_t *) (dip)) = *((ipaddr_t *) (sip)))
#define ismyip(ipaddr)	((getip(ipaddr)) == getip(myipaddr))

#define getnetid(ip)	((*((ipaddr_t *)(ip))) & (*((ipaddr_t *) mynetmask)))
#define ismynet(ip)	((getnetid(ip)) == getnetid(myipaddr))

/******
 ******	utilities
 ******/

extern void		pkt_main(pcap_t *fp, struct pcap_pkthdr	*header, unsigned char *pkt_data);
extern int		pkt_loop(pcap_t *fp, int loop);

extern int		readready();
extern char		*time2decstr(time_t t);
extern ipaddr_t		my_inet_addr(char *ip);
extern char		*ip_addrstr(unsigned char *ip, char *buf);
extern char		*eth_macaddr(const unsigned char *a, char *buf);

extern void		print_ip(unsigned char *ip, char *msg);
extern void		print_data(const unsigned char *data, int len);
extern char		*trimright(char *str);

extern unsigned short	swap16(unsigned short s);
extern unsigned long	swap32(unsigned long val);
extern unsigned short	checksum(char *ptr, int len);

#endif /* __COMMON_H__ */
