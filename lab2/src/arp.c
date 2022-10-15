#include "arp.h"

#include <stdio.h>
#include <string.h>

#include "common.h"
#include "mypcap.h"

const uint8_t eth_broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t eth_null_addr[] = {0, 0, 0, 0, 0, 0};

static const char *arp_op_str(uint16_t op);
static void arp_dump(myarp_t *arp);

/**
 * arp_request() - Send a ARP request for <IP> address
 **/
void arp_request(mypcap_t *p, uint8_t *ip) {
  eth_hdr_t eth_hdr;
  myarp_t pkt;

  if (ip == NULL) ip = defarpip;
  COPY_ETH_ADDR(eth_hdr.eth_dst, eth_broadcast_addr);
  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = ETH_ARP;

  pkt.ethtype = ARP_ETH_TYPE;
  pkt.iptype = ETH_IP;
  pkt.ethlen = ETH_ADDR_LEN;
  pkt.iplen = IPV4_ADDR_LEN;
  pkt.op = ARP_OP_REQUEST;
  COPY_ETH_ADDR(pkt.srceth, myethaddr);
  COPY_IPV4_ADDR(pkt.srcip, myipaddr);
  COPY_ETH_ADDR(pkt.dsteth, eth_null_addr);
  COPY_IPV4_ADDR(pkt.dstip, ip);

#if (DEBUG_ARP_REQUEST == 1)
  printf("arp_request() to %s\n", ip_addrstr(ip, NULL));
  arp_dump(&pkt);
#endif /* DEBUG_ARP_REQUEST */

  if (mypcap_send(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP request.\n");
  }
}

/**
 * arp_reply() - Reply the configured hardware address
 **/
void arp_reply(mypcap_t *p, uint8_t *dsteth, uint8_t *dstip) {
  eth_hdr_t eth_hdr;
  myarp_t pkt;

  COPY_ETH_ADDR(eth_hdr.eth_dst, dsteth);
  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = ETH_ARP;

  pkt.ethtype = ARP_ETH_TYPE;
  pkt.iptype = ETH_IP;
  pkt.ethlen = ETH_ADDR_LEN;
  pkt.iplen = IPV4_ADDR_LEN;
  pkt.op = ARP_OP_REPLY;
  COPY_ETH_ADDR(pkt.srceth, myethaddr);
  COPY_IPV4_ADDR(pkt.srcip, myipaddr);
  COPY_ETH_ADDR(pkt.dsteth, dsteth);
  COPY_IPV4_ADDR(pkt.dstip, dstip);

#if (DEBUG_ARP_REPLY == 1)
  printf("arp_reply() to %s\n", ip_addrstr(dstip, NULL));
#endif /* DEBUG_ARP_REPLY */

  if (mypcap_send(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP reply.\n");
  }
}

/**
 * arp_main() - The handler for incoming APR packets
 **/
void arp_main(mypcap_t *p, uint8_t *pkt, unsigned int len) {
  myarp_t *arp;

  arp = (myarp_t *)pkt;

#if (DEBUG_ARP == 1)
  arp_dump(arp);
#endif /* DEBUG_ARP */

  /* ARP request to My IP: reply it */
  switch (arp->op) {
    case ARP_OP_REQUEST: /* ARP Request */
      if (memcmp(arp->dstip, myipaddr, IPV4_ADDR_LEN) == 0)
        arp_reply(p, arp->srceth, arp->srcip);
      break;

    case ARP_OP_REPLY: /* ARP Reply */
      break;

#if (DEBUG_ARP == 1)
    default:
      printf("unknown ARP opcode\n");
#endif /* DEBUG_ARP */
  }
}

/**
 * arp_op_str() - Convert the operation code to human-readable string
 **/
static const char *arp_op_str(uint16_t op) {
  switch (op) {
    case ARP_OP_REPLY:
      return "Reply";
    case ARP_OP_REQUEST:
      return "Request";
    default:
      return "Unknown";
  }
}

/**
 * arp_dump() - Format output the content of ARP packet
 **/
static void arp_dump(myarp_t *arp) {
  char srceth[BUFLEN_ETH], srcip[BUFLEN_IP];
  char dsteth[BUFLEN_ETH], dstip[BUFLEN_IP];
  printf(
      "ARP Eth=%04x/%d, IP=%04x/%d, Op=%04x(%s)\n"
      "\tFrom %s (%s)\n"
      "\tTo   %s (%s)\n",
      swap16(arp->ethtype), arp->ethlen, swap16(arp->iptype), arp->iplen,
      swap16(arp->op), arp_op_str(arp->op), eth_macaddr(arp->srceth, srceth),
      ip_addrstr(arp->srcip, srcip), eth_macaddr(arp->dsteth, dsteth),
      ip_addrstr(arp->dstip, dstip));
}