#include "udp.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "dns.h"
#include "ip.h"

/******
 ******
 ******/

uint16_t udp_checksum(myip_param_t *ip_param, myudp_hdr_t *udp_hdr) {
  uint16_t oldchksum, newchksum;
  uint16_t *srcip2, *dstip2;
  uint32_t sum;
  int udplen;

  udplen = swap16(udp_hdr->length);
  /* checksum: pseudo header */
  srcip2 = (uint16_t *)ip_param->srcip;
  dstip2 = (uint16_t *)ip_param->dstip;
  sum = swap16(*srcip2) + swap16(*(srcip2 + 1)) + swap16(*dstip2) +
        swap16(*(dstip2 + 1)) + ip_param->protocol + udplen;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);

  /* checksum: udp packet */
  oldchksum = udp_hdr->chksum;
  udp_hdr->chksum = swap16((uint16_t)sum);
  newchksum = checksum((uint8_t *)&udp_hdr->srcport, udplen);
  udp_hdr->chksum = oldchksum;

  return newchksum;
}

void udp_main(mypcap_t *p, uint8_t *pkt, int len) {
  myip_hdr_t *ip_hdr;
  myudp_hdr_t *udp_hdr;
  int ip_hdr_len;

  ip_hdr = (myip_hdr_t *)pkt;
  ip_hdr_len = hlen(ip_hdr) * 4;
  pkt += ip_hdr_len;
  len -= ip_hdr_len;

  udp_hdr = (myudp_hdr_t *)pkt;

  assert(swap16(udp_hdr->length) == len);

#if (DEBUG_CHECKSUM == 1)
  myip_param_t ip_param;
  COPY_IPV4_ADDR(ip_param.srcip, ip_hdr->srcip);
  COPY_IPV4_ADDR(ip_param.dstip, ip_hdr->dstip);
  ip_param.protocol = ip_hdr->protocol;
  uint16_t chk = udp_checksum(&ip_param, udp_hdr);
#else
  uint16_t chk = 0;
#endif /* DEBUG_CHECKSUM */

  uint16_t srcport, dstport;

  srcport = swap16(udp_hdr->srcport);
  dstport = swap16(udp_hdr->dstport);

#if (DEBUG_UDP == 1 || DEBUG_CHECKSUM == 1)
  printf("UDP: %d->%d, Len=%d, chksum=%04x/%04x\n", srcport, dstport, len,
         (int)udp_hdr->chksum, chk);
#endif /* DEBUG_UDP == 1 || DEBUG_CHECKSUM == 1*/
#if (DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_UDP_DUMP == 1)
  print_data((uint8_t *)pkt, len);
#endif /* DEBUG_UDP_DUMP */

  switch (srcport) {
    case UDP_PORT_DNS:
      dns_main(p, ip_hdr, pkt, len);
      break;
  }
}

void udp_send(mypcap_t *p, myudp_param_t udp_param, uint8_t *payload,
              int payload_len) {
  int hdr_len = sizeof(myudp_hdr_t);
  int pkt_len = payload_len + hdr_len;
  uint8_t pkt[pkt_len];
  myudp_hdr_t *udp_hdr = (myudp_hdr_t *)pkt;
  myip_param_t *ip_param;

  ip_param = &udp_param.ip;
  ip_param->protocol = 0x11; /* UDP */
  COPY_IPV4_ADDR(ip_param->srcip, myipaddr);

  udp_hdr->srcport = swap16(udp_param.srcport);
  udp_hdr->dstport = swap16(udp_param.dstport);
  udp_hdr->length = swap16(pkt_len);
  udp_hdr->chksum = udp_checksum(ip_param, udp_hdr);

  memcpy(pkt + sizeof(myudp_hdr_t), payload, payload_len);

#if (DEBUG_UDP)
  printf("udp_send(): %d->%s:%d, Len=%d, chksum=%04x\n", (int)udp_param.srcport,
         ip_addrstr(ip_param->dstip, NULL), (int)udp_param.dstport, pkt_len,
         udp_hdr->chksum);
#endif /* DEBUG_UDP */
#if (DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_UDP_DUMP == 1)
  print_data((uint8_t *)pkt, pkt_len);
#endif /* DEBUG_UDP_DUMP */
  ip_send(p, ip_param, pkt, pkt_len);
}
