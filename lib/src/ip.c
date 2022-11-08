#include "ip.h"

#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "icmp.h"
#include "netdevice.h"
#include "tcp.h"
#include "udp.h"
#include "util.h"

/**
 * ip_checksum() - The utility to calculate the checksum of IP header.
 **/
uint16_t ip_checksum(myip_hdr_t *ip) {
  uint16_t oldchksum, newchksum;

  oldchksum = ip->chksum;
  ip->chksum = 0;
  newchksum = checksum((uint8_t *)ip, hlen(ip) * 4);
  ip->chksum = oldchksum;
  return newchksum;
}

/*
 * ip_main() - The handler to process the packets from the bottom layer.
 */
void ip_main(netdevice_t *p, uint8_t *pkt, int len) {
  myip_hdr_t *ip_hdr;

  ip_hdr = (myip_hdr_t *)pkt;

  int ip_len = swap16(ip_hdr->length);

  char srcip[BUFLEN_IP];
  char dstip[BUFLEN_IP];

#if (DEBUG_IP_CHECKSUM == 1)
  uint16_t chk = ip_checksum(ip_hdr);
  ;
#else
  uint16_t chk = 0;
#endif /* DEBUG_IP_CHECKSUM */

#if (DEBUG_IP >= 1 || DEBUG_IP_CHECKSUM == 1)
  printf("IP from %s to %s: Proto=%d, Len=%d, chksum=%04x/%04x\n",
         ip_addrstr(ip_hdr->srcip, srcip), ip_addrstr(ip_hdr->dstip, dstip),
         (int)ip_hdr->protocol, ip_len, (int)chk, (int)ip_hdr->chksum);
#endif /* DEBUG_IP == 1 || DEBUG_IP_CHECKSUM == 1 */

  switch (ip_hdr->protocol) {
    case IP_PROTO_ICMP: /* 0x01 */
      icmp_main(p, pkt, len);
      break;
    case IP_PROTO_TCP: /* 0x06 */
      tcp_main(p, pkt, len);
      break;
    case IP_PROTO_UDP: /* 0x11 */
      udp_main(p, pkt, len);
      break;
#if (DEBUG_IP == 2)
    default:
      printf("Unsupported IP protocol: %d\n", (int)ip_hdr->protocol);
#endif /* DEBUG_IP == 1 */
  }
}

/*
 * ip_send() - Send out a IP packet to the bottom layer with the payload from
 * the upper layer.
 */
void ip_send(netdevice_t *p, myip_param_t *ip_param, uint8_t *payload,
             int payload_len) {
  int hdr_len = sizeof(myip_hdr_t);
  int pkt_len = payload_len + hdr_len;
  myip_hdr_t ip_hdr;
  uint8_t pkt[MAX_CAP_LEN];
  uint8_t *dstip;

  /* Fill up the header of IP */
  ip_hdr.verhlen = verhlen(IP_VERSION, IP_MIN_HLEN);
  ip_hdr.servicetype = 0;
  ip_hdr.length = swap16((uint16_t)pkt_len);
  ip_hdr.identification = ip_hdr.fragoff = 0;
  ip_hdr.ttl = IP_MAX_TTL;
  ip_hdr.protocol = ip_param->protocol;
  ip_hdr.chksum = 0;
  SET_IP(ip_hdr.srcip, ip_param->srcip);
  SET_IP(ip_hdr.dstip, ip_param->dstip);

  /* Re-calculate the checksum */
  ip_hdr.chksum = ip_checksum(&ip_hdr);

  /* Construct the packet */
  memcpy(pkt, &ip_hdr, hdr_len);
  memcpy(pkt + hdr_len, payload, payload_len);

  /* Send to dafault gateway if destnation is not in the same network */
  dstip = IS_MY_NET(ip_hdr.dstip) ? ip_hdr.dstip : myrouterip;
#if (DEBUG_IP == 1)
  printf("ip_send (dstip=%s, proto=%d, iplen=%d) to ",
         ip_addrstr(ip_hdr.dstip, NULL), ip_hdr.protocol, ip_hdr.length);
  print_ip(dstip, "\n");
#endif /* DEBUG_IP == 1 */
  arp_send(p, dstip, ETH_IP, pkt, pkt_len);
}
