#include "netdevice.h"

#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

static void _capture_callback(unsigned char *arg,
                             const struct pcap_pkthdr *header,
                             const unsigned char *content);

/**
 * netdevice_getdevice() - Interactively ask user what interface to use
 * If defn is non zero, will select desired interface
 **/
int netdevice_getdevice(unsigned int defn, char *devname) {
  pcap_if_t *alldevs, *d;
  unsigned int selected_dev, dev_cnt = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  char buf[MAX_LINEBUF];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "%s(): Error in pcap_findalldevs: %s\n", __func__, errbuf);
    return NETDEVICE_ERR;
  }

  if (defn > 0) {
    selected_dev = defn;
  } else {
    /*
     * Print the list of avaliable interfaces
     */
    printf("Device list:\n");
    for (d = alldevs; d; d = d->next) {
      printf("%d. %s\n", ++dev_cnt, d->name);

      if (d->description) {
        printf("    (%s)\n", d->description);
      } else {
        printf("    (No description available)\n");
      }
    }

    /*
     * If there's no avaliable interface, abort and free the resources
     */
    if (dev_cnt == 0) {
      fprintf(stderr, "No interfaces found!\n");
      /*
       * Free the resources of the device list
       */
      pcap_freealldevs(alldevs);
      return NETDEVICE_ERR;
    }

    printf("Enter the interface number (1-%d):", dev_cnt);
    fgets(buf, MAX_LINEBUF, stdin);
    sscanf(buf, "%d", &selected_dev);
  }

  if (selected_dev < 1 || selected_dev > dev_cnt) {
    printf("\nInterface number out of range.\n");
    return NETDEVICE_ERR;
  } else {
    /*
     * Jump to the selected interface
     */
    for (d = alldevs; selected_dev - 1 > 0; d = d->next, selected_dev--)
      ;
    strcpy(devname, d->name);
  }
  /*
   * Free the resources of the device list
   */
  pcap_freealldevs(alldevs);
  return 0;
}

/**
 * netdevice_open() - Open a capture interface and initialize necessary
 * resources The capture interface will be put into non-blocking mode
 */
netdevice_t *netdevice_open(char *devname, char *errbuf) {
  netdevice_t *p = (netdevice_t *)calloc(1, sizeof(netdevice_t));
  p->plist = NULL;

  /*
   * Open the capture handle of pcap
   */
  if ((p->capture_handle = pcap_open_live(devname, MAX_CAP_LEN /* snaplen*/,
                                          PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                                          CAP_TIMEOUT /* read timeout (msec) */,
                                          errbuf /* error buf */)) == NULL) {
    free(p);
    return NULL;
  }

  /*
   * Put the capture device into non-blocking mode
   */
  if (pcap_setnonblock(p->capture_handle, 1, errbuf) != 0) {
    netdevice_close(p);
    return NULL;
  }

  return p;
}

/**
 * netdevice_add_proto() - Register a protocol handler of the upper layer with
 * specified ethertype
 */
int netdevice_add_proto(netdevice_t *p, uint16_t eth_type,
                        ptype_handler callback) {
  ptype_t *new_ptype;
  new_ptype = (ptype_t *)calloc(1, sizeof(ptype_t));
  new_ptype->eth_type = eth_type;
  new_ptype->callback = callback;
  new_ptype->p = p;

  /*
   * Append new node to the linked list
   */
  new_ptype->next = p->plist;
  p->plist = new_ptype;

  return 0;
}

/**
 * netdevice_rx() - Process all of the packets in the capture buffer.
 * The detailed procedure to deal the packets is in capture_callback()
 */
int netdevice_rx(netdevice_t *p) {
  /*
   * Process all of the packet in the capture buffer.
   * pcap_dispatch() may return after capture buffer timeout.
   */
  int pkt_cnt = pcap_dispatch(p->capture_handle, -1, _capture_callback,
                              (unsigned char *)p);
  if (pkt_cnt < 0) {
    fprintf(stderr, "%s(): Failed to read the packets: %s\n", __func__,
            pcap_geterr(p->capture_handle));
    return -1;
  }

  return pkt_cnt;
}

/**
 * netdevice_xmit() - Send out an Ethernet frame with the given Ethernet header
 * and payloads. The frame will be padded with '\0' to meet the minimal length
 * of the Ethernet frame.
 */
int netdevice_xmit(netdevice_t *p, eth_hdr_t eth_hdr, uint8_t *payload,
                   int payload_len) {
  uint8_t buf[MAX_CAP_LEN];
  const int hdr_len = sizeof(eth_hdr_t);
  int pktlen = hdr_len + payload_len;

  /*
   * Build the packet
   */
  memcpy(buf, &eth_hdr, hdr_len);
  memcpy(buf + hdr_len, payload, payload_len);
  if (pktlen < MIN_ETH_LEN) {
    /*
     * Padding the packet so that the length of the packet meets the minimal
     * requirement of Ethernet frame
     */
    memset(buf + pktlen, 0, MIN_ETH_LEN - pktlen);
    pktlen = MIN_ETH_LEN;
  }

#if (DEBUG_PACKET == 1)
  char src_addr[BUFLEN_ETH], dst_addr[BUFLEN_ETH];
  time_t current_time;
  time(&current_time);
  /*
   * Print timestamp and length of the packet.
   */
  eth_macaddr(eth_hdr.eth_src, src_addr);
  eth_macaddr(eth_hdr.eth_dst, dst_addr);
  printf("<< %s %s=>%s (Type=%.04x/Len=%d)\n", time2decstr(current_time),
         src_addr, dst_addr, swap16(eth_hdr.eth_type), pktlen);
#endif /* DEBUG_PACKET */

  if (pcap_sendpacket(p->capture_handle, buf, pktlen) != 0) {
    fprintf(stderr, "\n%s(): Failed to send the packet: %s\n", __func__,
            pcap_geterr(p->capture_handle));
    return -1;
  }
  return 0;
}

/**
 * netdevice_close() - Close the capture interface and release all of the
 * resources.
 */
void netdevice_close(netdevice_t *p) {
  ptype_t *d, *tmp;

  /*
   * Free the space of packet list
   */
  d = p->plist;
  while (d != NULL) {
    tmp = d;
    d = d->next;
    free(tmp);
  }

  /*
   * Free the space of handler
   */
  pcap_close(p->capture_handle);
  free(p);

  return;
}

/**
 * _capture_callback() - The main body to handle received packets.
 * The Ethernet frame header of arrived packets will be parsed.
 * The payload of packets will be distributed based on their ethertype.
 * The handler of the upper layer won't be able to see the content of the
 * Ethernet header.
 */
static void _capture_callback(unsigned char *arg,
                             const struct pcap_pkthdr *header,
                             const unsigned char *pkt_data) {
  netdevice_t *p = (netdevice_t *)(arg);
  ptype_t *d;
  eth_hdr_t *eth_hdr;
  const uint8_t *payload = pkt_data + sizeof(eth_hdr_t);
  int pktlen, payload_len;

  eth_hdr = (eth_hdr_t *)pkt_data;
  pktlen = header->caplen;
  payload_len = pktlen - sizeof(eth_hdr_t);
#if (DEBUG_PACKET == 1)
  char src_addr[BUFLEN_ETH], dst_addr[BUFLEN_ETH];
  /*
   * Print timestamp and length of the packet.
   */
  eth_macaddr(eth_hdr->eth_src, src_addr);
  eth_macaddr(eth_hdr->eth_dst, dst_addr);
  printf("*%s %s=>%s (Type=%.04x/Len=%d)\n", time2decstr(header->ts.tv_sec),
         src_addr, dst_addr, swap16(eth_hdr->eth_type), header->len);
#endif /* DEBUG_PACKET */

#if (DEBUG_PACKET_DUMP == 1)
  /*
   * Print the content of the packet
   */
  print_data(pkt_data, pktlen);
#endif /* DEBUG_PACKET_DUMP */

  /*
   * Iterate the whole protocol list to find the matched handler
   */
  for (d = p->plist; d != NULL; d = d->next) {
    if (eth_hdr->eth_type == d->eth_type) {
      d->callback(d->p, payload, payload_len);
      break;
    }
  }
}