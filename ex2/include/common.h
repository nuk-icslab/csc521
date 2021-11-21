#ifndef __COMMON_H__
#define __COMMON_H__

#include <errno.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

#define FG_NATIVE_CYGWIN 1

#define FG_ARP_SEND_REQUEST 1

/***
 *** Flags
 ***/

#define DEBUG_PACKET 1
#define DEBUG_PACKET_DUMP 1
#define DEBUG_ARP 1
#define DEBUG_ARP_REQUEST 1
#define DEBUG_ARP_REPLY 1
#define DEBUG_ARP_DUMP 1

#define MAX_CAP_LEN 1514
#define MAX_DUMP_PKT 5
#define CAP_TIMEOUT 100

#define BUFLEN_ETH 18
#define BUFLEN_IP 16
#define MAX_DUMP_LEN 80
#define MAX_LINE_LEN 16
#define MAX_LINEBUF 256

/***
 *** Assigned Numbers and Prameters
 ***/

#define MIN_ETH_LEN 64

#define ETH_IP 0x0008
#define ETH_ARP 0x0608

#define ETH_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

typedef struct {
  uint8_t eth_dst[ETH_ADDR_LEN];
  uint8_t eth_src[ETH_ADDR_LEN];
  uint16_t eth_type;
} eth_hdr_t;

#define COPY_ETH_ADDR(dst, src) (memcpy((dst), (src), ETH_ADDR_LEN))
#define COPY_IPV4_ADDR(dst, src) (memcpy((dst), (src), IPV4_ADDR_LEN))

typedef uint32_t ipaddr_t;

/******
 ****** from config.c
 ******/

extern uint8_t myethaddr[ETH_ADDR_LEN];
extern uint8_t myipaddr[IPV4_ADDR_LEN];
extern uint8_t defarpip[IPV4_ADDR_LEN];

#define getip(ipaddr) (*((ipaddr_t *)(ipaddr)))
#define ismyip(ipaddr) ((getip(ipaddr)) == getip(myipaddr))

/******
 ****** utilities
 ******/

extern int readready();
extern char *time2decstr(time_t t);
extern ipaddr_t my_inet_addr(char *ip);
extern char *ip_addrstr(unsigned char *ip, char *buf);
extern char *eth_macaddr(const unsigned char *a, char *buf);

extern void print_ip(unsigned char *ip, char *msg);
extern void print_data(const unsigned char *data, int len);
extern uint16_t swap16(uint16_t x);

/******
 ****** constants
 ******/

extern const uint8_t eth_broadcast_addr[ETH_ADDR_LEN];
extern const uint8_t eth_null_addr[ETH_ADDR_LEN];

#endif /* __COMMON_H__ */
