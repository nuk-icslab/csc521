#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "common.h"
#include "dns.h"
#include "icmp.h"
#include "mypcap.h"
#include "tcp.h"

// // [TODO] Remove pkt_main
// void pkt_main(pcap_t *fp, struct pcap_pkthdr *header, uint8_t *pkt_data) {
//   myeth_t *pkt = (myeth_t *)pkt_data;
//   int pktlen = header->caplen;
// #if (DEBUG_PACKET == 1)
//   char addrsrc[BUFLEN_ETH], addrdst[BUFLEN_ETH];
// #endif /* DEBUG_PACKET */

// #if (DEBUG_PACKET == 1)
//   /* print pkt timestamp and pkt len */
//   printf("*%s %s=>%s (Type=%.2x%.2x/Len=%ld)\n",
//   time2decstr(header->ts.tv_sec),
//          eth_macaddr(pkt_data + 6, addrsrc), eth_macaddr(pkt_data, addrdst),
//          pkt_data[12], pkt_data[13], header->len);
// #endif /* DEBUG_PACKET */
// #if (DEBUG_PACKET_DUMP == 1)
//   print_data(pkt_data, pktlen);
// #endif /* DEBUG_PACKET_DUMP */
//   switch (pkt->eth_type) {
//     case ETH_ARP:
//       arp_main(fp, (uint8_t *)pkt_data, pktlen);
//       break;
//     case ETH_IP:
//       ip_main(fp, (uint8_t *)pkt_data, pktlen);
//       break;
//   }
// }

// // [TODO] Remove pkt_loop
// int pkt_loop(pcap_t *fp, int loop) {
//   int i, res;
//   struct pcap_pkthdr *header;
//   const uint8_t *pkt_data;

//   /*---- Read the packets */
//   for (i = 0; loop == 0 || i < loop; i++) {
//     if ((res = pcap_next_ex(fp, &header, &pkt_data)) == -1) {
//       fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
//       return -1;
//     }
//     if (res > 0) pkt_main(fp, header, (uint8_t *)pkt_data);

//     if (readready() != 0) break;
//   }

//   /*---- exit */
//   return 0; /* expired */
// }

/**
 * main_proc() - the main thread
 **/
int main_proc(mypcap_t *p) {
  char buf[MAX_LINEBUF];
  ipaddr_t ip;
  int key;

#if (FG_ARP_SEND_REQUEST == 1)
  arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */
#if (FG_ICMP_SEND_REQUEST == 1)
  icmp_ping(p, NULL);
#endif /* FG_ICMP_SEND_REQUEST */

  /* Read the packets */
  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (mypcap_proc(p) == -1) {
      break;
    }

    /*----------------------------------*
     * Other works can be inserted here *
     *----------------------------------*/

    /* key pressed? */
    if (!readready()) continue;
    if ((key = fgetc(stdin)) == '\n') break;
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
    trimright(buf);
    if ((ip = retrieve_ip_addr(buf)) != 0 || (ip = resolve(p, buf)) != 0) {
#if (FG_DNS_DO_PING == 1)
      icmp_ping(p, (uint8_t *)&ip);
#else
      printf("%s\t%s\n", buf, ip_addrstr(ip, NULL));
#endif /* FG_DNS_DO_PING */
    } else {
      printf("Invalid IP (Enter to exit)\n");
    }
  }

  return 0;
}

/****
 ****	MAIN ENTRY
 ****/

int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  mypcap_t *p;

  /*
   * Get the device name of capture interface
   */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (mypcap_getdevice(0, devname) == MYPCAP_ERR) {
    return -1;
  }

  /*
   * Open the specified interface
   */
  if ((p = mypcap_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  /*
   * Register the packet handler callback of specific protocol
   */
  mypcap_add_prot(p, ETH_ARP, (mypcap_handler)&arp_main);
  mypcap_add_prot(p, ETH_IP, (mypcap_handler)&ip_main);

  main_proc(p);

  /*
   * Clean up the resources
   */
  mypcap_close(p);
}