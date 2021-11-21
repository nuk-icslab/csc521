#include "mypcap.h"

#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static void capture_callback(unsigned char *arg,
                             const struct pcap_pkthdr *header,
                             const unsigned char *content);

int mypcap_getdevice(unsigned int defn, char *devname) {
  pcap_if_t *alldevs, *d;
  unsigned int selected_dev, dev_cnt = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  char buf[MAX_LINEBUF];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "mypcap_getdevice(): Error in pcap_findalldevs: %s\n",
            errbuf);
    return MYPCAP_ERR;
  }

  if (defn > 0) {
    selected_dev = defn;
  } else {
    /* Print the list */
    printf("Device list:\n");
    for (d = alldevs; d; d = d->next) {
      printf("%d. %s\n", ++dev_cnt, d->name);

      if (d->description) {
        printf("    (%s)\n", d->description);
      } else {
        printf("    (No description available)\n");
      }
    }

    if (dev_cnt == 0) {
      fprintf(stderr, "No interfaces found!\n");
      /* Free the device list */
      pcap_freealldevs(alldevs);
      return MYPCAP_ERR;
    }

    printf("Enter the interface number (1-%d):", dev_cnt);
    fgets(buf, MAX_LINEBUF, stdin);
    sscanf(buf, "%d", &selected_dev);
  }

  if (selected_dev < 1 || selected_dev > dev_cnt) {
    printf("\nInterface number out of range.\n");
    return MYPCAP_ERR;
  } else {
    /* Jump to the selected adapter */
    for (d = alldevs; selected_dev - 1 > 0; d = d->next, selected_dev--)
      ;
    strcpy(devname, d->name);
  }
  /* Free the device list */
  pcap_freealldevs(alldevs);
  return 0;
}

mypcap_t *mypcap_open(char *devname, char *errbuf) {
  mypcap_t *p = (mypcap_t *)calloc(1, sizeof(mypcap_t));
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
    mypcap_close(p);
    return NULL;
  }

  return p;
}

int mypcap_add_prot(mypcap_t *p, uint16_t eth_type, mypcap_handler callback) {
  mypcap_prot_t *new_prot;
  new_prot = (mypcap_prot_t *)calloc(1, sizeof(mypcap_prot_t));
  new_prot->eth_type = eth_type;
  new_prot->callback = callback;
  new_prot->p = p;

  /*
   * Append new node to the linked list
   */
  new_prot->next = p->plist;
  p->plist = new_prot;

  return 0;
}
int mypcap_proc(mypcap_t *p) {
  /*
   * Process all of the packet in the capture buffer.
   * pcap_dispatch() may return after capture buffer timeout.
   */
  int pkt_cnt = pcap_dispatch(p->capture_handle, -1, capture_callback,
                              (unsigned char *)p);
  if (pkt_cnt < 0) {
    fprintf(stderr, "mypcap_proc(): Failed to read the packets: %s\n",
            pcap_geterr(p->capture_handle));
    return -1;
  }

  return pkt_cnt;
}
int mypcap_send(mypcap_t *p, eth_hdr_t eth_hdr, uint8_t *payload,
                int payload_len) {
  uint8_t buf[MAX_CAP_LEN];
  char src_addr[BUFLEN_ETH], dst_addr[BUFLEN_ETH];
  const int hdr_len = sizeof(eth_hdr_t);
  int pktlen = hdr_len + payload_len;

  /*
   * Build the packet
   */
  memcpy(buf, &eth_hdr, hdr_len);
  memcpy(buf + hdr_len, payload, payload_len);
  if (pktlen < MIN_ETH_LEN) {
    // Padding the packet so that the length of the packet meets the minimal
    // requirement of Ethernet frame
    memset(buf + pktlen, 0, MIN_ETH_LEN - pktlen);
    pktlen = MIN_ETH_LEN;
  }

#if (DEBUG_PACKET == 1)
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
    fprintf(stderr, "\nmypcap_send(): Failed to send the packet: %s\n",
            pcap_geterr(p->capture_handle));
    return -1;
  }
  return 0;
}

void mypcap_close(mypcap_t *p) {
  mypcap_prot_t *d, *tmp;

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

static void capture_callback(unsigned char *arg,
                             const struct pcap_pkthdr *header,
                             const unsigned char *pkt_data) {
  mypcap_t *p = (mypcap_t *)(arg);
  mypcap_prot_t *d;
  eth_hdr_t *eth_hdr;
  const uint8_t *payload = pkt_data + sizeof(eth_hdr_t);
  int pktlen, payload_len;
  char src_addr[BUFLEN_ETH], dst_addr[BUFLEN_ETH];

  eth_hdr = (eth_hdr_t *)pkt_data;
  pktlen = header->caplen;
  payload_len = pktlen - sizeof(eth_hdr_t);
#if (DEBUG_PACKET == 1)
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