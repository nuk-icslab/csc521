#ifndef MYPCAP_H
#define MYPCAP_H

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
#define MYPCAP_ERR -1

/*===================================*
 ***** Data Structures and Types *****
 *===================================*/
typedef struct mypcap mypcap_t;
typedef struct mypcap_prot mypcap_prot_t;
typedef void (*mypcap_handler)(mypcap_t *fp, const uint8_t *pkt,
                               unsigned int len);

struct mypcap {
  pcap_t *capture_handle;
  mypcap_prot_t *plist;
};

struct mypcap_prot {
  uint16_t eth_type;
  mypcap_handler callback;
  mypcap_t *p;
  struct mypcap_prot *next;
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
extern int mypcap_getdevice(unsigned int defn, char *devname);
extern mypcap_t *mypcap_open(char *devname, char *errbuf);
extern int mypcap_add_prot(mypcap_t *p, uint16_t eth_type,
                           mypcap_handler callback);
extern int mypcap_proc(mypcap_t *p);
extern int mypcap_send(mypcap_t *p, eth_hdr_t eth_hdr, uint8_t *payload,
                       int payload_len);
extern void mypcap_close(mypcap_t *p);

#endif