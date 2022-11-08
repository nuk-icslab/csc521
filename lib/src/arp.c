#include "arp.h"

#include <stdio.h>

#include "ip.h"
#include "util.h"

const uint8_t eth_broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t eth_null_addr[] = {0, 0, 0, 0, 0, 0};

static const char *arp_op_str(uint16_t op);
static void arp_dump(myarp_t *arp);

/*
 * Tosend Queue with 1 Buffer (Pending for ARP)
 */

struct {
  uint8_t payload[MAX_CAP_LEN];
  int len;
  ipaddr_t dst_ip;
  uint16_t eth_type;
} tosend_queue = {.len = 0, .dst_ip = 0, .eth_type = 0};

/**
 * arp_request() - Send a ARP request for <IP> address
 **/
void arp_request(netdevice_t *p, uint8_t *ip) {
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

  if (netdevice_xmit(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP request.\n");
  }
}

/**
 * arp_reply() - Reply the configured hardware address
 **/
void arp_reply(netdevice_t *p, uint8_t *dsteth, uint8_t *dstip) {
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

  if (netdevice_xmit(p, eth_hdr, (uint8_t *)&pkt, sizeof(pkt)) != 0) {
    fprintf(stderr, "Failed to send ARP reply.\n");
  }
}

/**
 * arp_main() - The handler for incoming APR packets
 **/
void arp_main(netdevice_t *p, uint8_t *pkt, unsigned int len) {
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
      if (IS_MY_IP(arp->dstip)) arptable_add(arp->srcip, arp->srceth);
      if (tosend_queue.len > 0) {
        if ((GET_IP(arp->srcip)) == tosend_queue.dst_ip) {
          arp_resend(p);
        } else {
          printf("Resend ARP request to %s\n",
                 ip_addrstr((uint8_t *)&tosend_queue.dst_ip, NULL));
          /* If doesn't get response from desired IP,
             resend the ARP request */
          arp_request(p, (uint8_t *)&tosend_queue.dst_ip);
        }
      }
      break;

#if (DEBUG_ARP == 1)
    default:
      printf("unknown ARP opcode\n");
#endif /* DEBUG_ARP */
  }
}

/**
 * arp_send() - Send out packets from upper layer to the specificed destination
 * IP address.
 **/
void arp_send(netdevice_t *p, uint8_t *dst_ip, uint16_t eth_type, uint8_t *payload,
              int payload_len) {
  uint8_t *eth_dst;
  eth_hdr_t eth_hdr;

  COPY_ETH_ADDR(eth_hdr.eth_src, myethaddr);
  eth_hdr.eth_type = eth_type;

  if ((eth_dst = arptable_existed(dst_ip)) != NULL) {
    /* Send directly if MAC available */
    COPY_ETH_ADDR(eth_hdr.eth_dst, eth_dst);
    if (netdevice_xmit(p, eth_hdr, payload, payload_len) != 0) {
      fprintf(stderr, "Failed to send.\n");
    }
#if (DEBUG_ARP == 1)
    printf("arp_send(): Packet sent to %s (%s) eth_type=%04x\n",
           ip_addrstr(dst_ip, NULL), eth_macaddr(eth_dst, NULL),
           swap16(eth_type));
#if (DEBUG_ARP_DUMP == 1)
    print_data(payload, payload_len);
#endif  // DEBUG_ARP_DUMP == 1
#endif  // DEBUG_ARP == 1
  } else {
#if (DEBUG_ARP == 1)
    printf(
        "arp_send(): MAC address of %s is unavailable. "
        "The outgoing packet is queued.\n",
        ip_addrstr(dst_ip, NULL));
#endif
    /* Put to the queue and reqeust ARP if MAC unavailable */
    tosend_queue.dst_ip = GET_IP(dst_ip);
    tosend_queue.len = payload_len;
    tosend_queue.eth_type = eth_type;
    memcpy((uint8_t *)&tosend_queue.payload, payload, payload_len);
    arp_request(p, dst_ip);
  }
}

/**
 * arp_resend() - Re-send the queued packet
 **/
void arp_resend(netdevice_t *p) {
#if (DEBUG_ARP == 1)
  printf(
      "arp_resend(): Obtained the MAC address of %s. "
      "Re-sending queued packets.\n",
      ip_addrstr((uint8_t *)&tosend_queue.dst_ip, NULL));
#endif

  arp_send(p, (uint8_t *)&tosend_queue.dst_ip, tosend_queue.eth_type,
           tosend_queue.payload, tosend_queue.len);

  tosend_queue.len = 0;
  tosend_queue.dst_ip = 0;
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