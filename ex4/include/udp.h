#ifndef __UDP_H__
#define __UDP_H__

#include "ip.h"

/*=========================*
 ***** Protocol Format *****
 *=========================*/
typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  uint16_t length;
  uint16_t chksum;
} myudp_hdr_t;

typedef struct {
  uint16_t srcport;
  uint16_t dstport;
  myip_param_t ip;
} myudp_param_t;

// typedef struct {
//   uint8_t ip_verhlen;
//   uint8_t ip_servicetype;
//   uint16_t ip_length;

//   uint16_t ip_identification;
//   uint16_t ip_fragoff;

//   uint8_t ip_ttl;
//   uint8_t ip_protocol;
//   uint16_t ip_chksum;

//   uint8_t ip_srcip[4];
//   uint8_t ip_dstip[4];

//   uint16_t udp_srcport;
//   uint16_t udp_dstport;
//   uint16_t udp_length;
//   uint16_t udp_chksum;
//   uint8_t udp_data[1472]; /* 1500 - ip_header20 - udp_header8 */
// } myipudp_t;

/*========================*
 ***** Public Methods *****
 *========================*/
extern void udp_main(mypcap_t *p, uint8_t *pkt, int len);
extern void udp_send(mypcap_t *p, myudp_param_t udp_param, uint8_t *payload,
                     int payload_len);

/*===========================*
 ***** Private Utilities *****
 *===========================*/
extern uint16_t udp_checksum(myip_param_t *ip_param, myudp_hdr_t *udp_hdr);

#endif /* __UDP_H__ */
