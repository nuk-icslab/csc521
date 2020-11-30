#ifndef __COMMON_H__
#define __COMMON_H__

#include <pcap/pcap.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

#define FG_NATIVE_CYGWIN	1

#define FG_ARP_SEND_REQUEST	0
#define FG_ICMP_SEND_REQUEST	0
#define FG_DNS_DO_PING		1

/***
 ***	Flags
 ***/

#define DEBUG_PACKET		0
#define DEBUG_PACKET_DUMP	0

#define DEBUG_ARP		0
#define DEBUG_ARP_REQUEST	0
#define DEBUG_ARP_REPLY		0
#define DEBUG_ARP_DUMP		0
#define DEBUG_ARPCACHE		1

#define DEBUG_CHECKSUM		0

#define DEBUG_IP		0
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
	uint8_t	eth_dst[6];
	uint8_t	eth_src[6];
	uint16_t	eth_type;
	uint8_t	data[1];
} myeth_t;

typedef uint32_t	ipaddr_t;

/******
 ******
 ******/

extern uint8_t	myethaddr[6];
extern uint8_t	myipaddr[4];
extern uint8_t	myrouterip[4];
extern uint8_t	mynetmask[4];

extern uint8_t	defarpip[4];
extern uint8_t	defpingip[4];

#define getip(ipaddr)	(*((ipaddr_t *)(ipaddr)))
#define setip(dip, sip)	(*((ipaddr_t *) (dip)) = *((ipaddr_t *) (sip)))
#define ismyip(ipaddr)	((getip(ipaddr)) == getip(myipaddr))

#define getnetid(ip)	((*((ipaddr_t *)(ip))) & (*((ipaddr_t *) mynetmask)))
#define ismynet(ip)	((getnetid(ip)) == getnetid(myipaddr))

/******
 ******	utilities
 ******/

extern void		pkt_main(pcap_t *fp, struct pcap_pkthdr	*header, uint8_t *pkt_data);
extern int		pkt_loop(pcap_t *fp, int loop);

extern int		readready();
extern char		*time2decstr(time_t t);
extern ipaddr_t		my_inet_addr(char *ip);
extern char		*ip_addrstr(uint8_t *ip, char *buf);
extern char		*eth_macaddr(const uint8_t *a, char *buf);

extern void		print_ip(uint8_t *ip, char *msg);
extern void		print_data(const uint8_t *data, int len);
extern char		*trimright(char *str);

extern uint16_t	swap16(uint16_t s);
extern uint32_t	swap32(uint32_t val);
extern uint16_t	checksum(char *ptr, int len);

#endif /* __COMMON_H__ */
