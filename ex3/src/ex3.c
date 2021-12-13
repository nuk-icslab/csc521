#include <stdio.h>
#include <stdlib.h>
/* #include <windows.h> */

#include <pcap.h>

#include "arp.h"
#include "common.h"
#include "icmp.h"
#include "mypcap.h"

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
    if ((ip = retrieve_ip_addr(buf)) == 0) {
      printf("Invalid IP (Enter to exit)\n");
    } else {
      icmp_ping(p, (uint8_t *)&ip);
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
