#ifndef MYPCAP_H
#define MYPCAP_H

#include <pcap.h>

#include "common.h"

#define MAX_CAP_LEN 1514
#define CAP_TIMEOUT 100
#define MYPCAP_ERR -1

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

extern int mypcap_getdevice(unsigned int defn, char *devname);
extern mypcap_t *mypcap_open(char *devname, char *errbuf);
extern int mypcap_add_prot(mypcap_t *p, uint16_t eth_type,
                           mypcap_handler callback);
extern int mypcap_proc(mypcap_t *p);
extern int mypcap_send(mypcap_t *p, eth_hdr_t eth_hdr, uint8_t *payload,
                       int payload_len);
extern void mypcap_close(mypcap_t *p);

#endif