#include "tcp.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

#if (DEBUG_TCP == 1)
/*
 * tcp_flagstr() - Convert flags in TCP header to human-readable format
 */
static char *tcp_flagstr(uint8_t flags) {
  static char buf[7];

  buf[0] = ((flags & TCP_FG_URT) != 0) ? 'U' : '-';
  buf[1] = ((flags & TCP_FG_ACK) != 0) ? 'A' : '-';
  buf[2] = ((flags & TCP_FG_PSH) != 0) ? 'P' : '-';
  buf[3] = ((flags & TCP_FG_RST) != 0) ? 'R' : '-';
  buf[4] = ((flags & TCP_FG_SYN) != 0) ? 'S' : '-';
  buf[5] = ((flags & TCP_FG_FIN) != 0) ? 'F' : '-';
  buf[6] = '\0';
  return buf;
}
#endif  // DEBUG_TCP

static tcp_raw_handler raw_handler = NULL;

/*
 * tcp_checksum() - Calculate checksum of TCP segment with IPv4 pseudo header
 */
static uint16_t tcp_checksum(myip_param_t *ip_param, uint8_t *pkt, int tcplen) {
  mytcp_hdr_t *tcp_hdr = (mytcp_hdr_t *)pkt;
  uint16_t oldchksum, newchksum;
  uint16_t *srcip2, *dstip2;
  uint32_t sum;

  /* checksum: pseudo header */
  srcip2 = (uint16_t *)ip_param->srcip;
  dstip2 = (uint16_t *)ip_param->dstip;
  sum = swap16(*srcip2) + swap16(*(srcip2 + 1));
  sum += swap16(*dstip2) + swap16(*(dstip2 + 1));
  sum += ip_param->protocol + tcplen;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);

  /* checksum: tcp packet */
  oldchksum = tcp_hdr->chksum;
  tcp_hdr->chksum = swap16((uint16_t)sum);
  newchksum = checksum(pkt, tcplen);
  tcp_hdr->chksum = oldchksum;

  /* final */
  return newchksum;
}

/*
 * tcp_set_raw_handler(): Register the callback to handle raw TCP segments
 */
void tcp_set_raw_handler(tcp_raw_handler callback) { raw_handler = callback; }

/*
 * tcp_main(): The main procedure for incoming TCP segments
 */
void tcp_main(netdevice_t *p, uint8_t *pkt, int len) {
  myip_hdr_t *ip_hdr;
  mytcp_hdr_t *tcp_hdr;
  int ip_hdr_len, tcp_hdr_len;

  ip_hdr = (myip_hdr_t *)pkt;
  ip_hdr_len = hlen(ip_hdr) * 4;
  pkt += ip_hdr_len;
  len -= ip_hdr_len;

  tcp_hdr = (mytcp_hdr_t *)pkt;
  tcp_hdr_len = ((tcp_hdr->hlen) >> 3) * 4;
  pkt += tcp_hdr_len;
  len -= tcp_hdr_len;

#if (DEBUG_TCP == 1)
  myip_param_t ip_param;
  int tcp_len;
  COPY_IPV4_ADDR(ip_param.srcip, ip_hdr->srcip);
  COPY_IPV4_ADDR(ip_param.dstip, ip_hdr->dstip);
  ip_param.protocol = ip_hdr->protocol;
  tcp_len = len - hlen(ip_hdr) * 4;
  uint16_t chk = tcp_checksum(&ip_param, pkt, tcp_len);

  uint16_t srcport, dstport;

  srcport = swap16(tcp_hdr->srcport);
  dstport = swap16(tcp_hdr->dstport);

  printf("TCP %s: %d->%d, Len=%d, chksum=%04x/%04x\n",
         tcp_flagstr(tcp_hdr->flags), srcport, dstport, tcp_len,
         (int)tcp_hdr->chksum, chk);
#endif /* DEBUG_TCP */
#if (DEBUG_TCP_DUMP == 1)
  print_data((uint8_t *)tcp_hdr, tcp_hdr_len);
#endif /* DEBUG_TCP_DUMP */
  if (raw_handler) {
    (*raw_handler)(ip_hdr, tcp_hdr, pkt, len);
  }
}

void tcp_syn(netdevice_t *p, mytcp_param_t tcp_param, uint8_t *payload,
             int payload_len) {
  int hdr_len = sizeof(mytcp_hdr_t);
  int pkt_len = payload_len + hdr_len;
  uint8_t pkt[pkt_len];
  mytcp_hdr_t *tcp_hdr = (mytcp_hdr_t *)pkt;
  myip_param_t *ip_param;

  ip_param = &tcp_param.ip;
  ip_param->protocol = IP_PROTO_TCP; /* 0x06 */
  COPY_IPV4_ADDR(ip_param->srcip, myipaddr);

  tcp_hdr->srcport = swap16(tcp_param.srcport);
  tcp_hdr->dstport = swap16(tcp_param.dstport);
  tcp_hdr->seq = 0;
  tcp_hdr->ack = 0;
  tcp_hdr->hlen = TCP_MIN_HLEN;
  tcp_hdr->flags = 0;
  tcp_hdr->flags |= TCP_FG_SYN;
  tcp_hdr->window = swap16(TCP_DEF_WINDOW);
  tcp_hdr->urgent = 0;
  tcp_hdr->chksum = tcp_checksum(ip_param, pkt, pkt_len);

  memcpy(pkt + sizeof(mytcp_hdr_t), payload, payload_len);

#if (DEBUG_TCP)
  printf("tcp_syn(): %d->%s:%d, %s Len=%d, chksum=%04x\n",
         (int)tcp_param.srcport, ip_addrstr(ip_param->dstip, NULL),
         (int)tcp_param.dstport, tcp_flagstr(tcp_hdr->flags), pkt_len,
         tcp_hdr->chksum);
#endif /* DEBUG_TCP */
#if (DEBUG_TCP_DUMP == 1)
  print_data((uint8_t *)pkt, pkt_len);
#endif /* DEBUG_TCP_DUMP */

  ip_send(p, ip_param, pkt, pkt_len);
}
