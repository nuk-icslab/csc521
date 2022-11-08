#ifndef NETDEVICE_H
#define NETDEVICE_H

#include <pcap.h>

#include "util.h"

/*
 * Control flags
 */
#ifndef DEBUG_PACKET
#define DEBUG_PACKET 0
#endif  // DEBUG_PACKET
#ifndef DEBUG_PACKET_DUMP
#define DEBUG_PACKET_DUMP 0
#endif  // DEBUG_PACKET_DUMP

/*
 * For libpcap that doesn't support WinPcap
 */
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif  // PCAP_OPENFLAG_PROMISCUOUS

/*====================*
 ***** Parameters *****
 *====================*/
/*
 * The possible maximum Ethernet frame size without jumbo frame and frame check
 * sequence (FCS)
 */
#define MAX_CAP_LEN 1514

/*
 * The minimum size, excluding FCS, of Ethernet frame
 */
#define MIN_ETH_LEN 60

/*
 * The capture buffer timeout. All packets received in the same period will be
 * process at the same batch
 */
#define CAP_TIMEOUT 100

/*===================*
 ***** Constants *****
 *===================*/
#define NETDEVICE_ERR -1

/*===================================*
 ***** Data Structures and Types *****
 *===================================*/
typedef struct netdevice netdevice_t;
typedef struct ptype ptype_t;
typedef void (*ptype_handler)(netdevice_t *fp, const uint8_t *pkt,
                               unsigned int len);

struct netdevice {
  pcap_t *capture_handle;
  ptype_t *plist;
};

struct ptype {
  uint16_t eth_type;
  ptype_handler callback;
  netdevice_t *p;
  struct ptype *next;
};

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint8_t eth_dst[ETH_ADDR_LEN];
  uint8_t eth_src[ETH_ADDR_LEN];
  uint16_t eth_type;
} eth_hdr_t;

/*========================*
 ***** Public Methods *****
 *========================*/
extern int netdevice_getdevice(unsigned int defn, char *devname);
extern netdevice_t *netdevice_open(char *devname, char *errbuf);
extern int netdevice_add_proto(netdevice_t *p, uint16_t eth_type,
                           ptype_handler callback);
extern int netdevice_rx(netdevice_t *p);
extern int netdevice_xmit(netdevice_t *p, eth_hdr_t eth_hdr, uint8_t *payload,
                       int payload_len);
extern void netdevice_close(netdevice_t *p);

#endif // NETDEVICE_h