#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arp.h"
#include "netdevice.h"
#include "util.h"

/**
 * main_proc() - The main body of this lab
 **/
int main_proc(netdevice_t *p) {
  int key;
  char buf[MAX_LINEBUF];
  ipaddr_t ip;

#if (FG_ARP_SEND_REQUEST == 1)
  /*
   * Send ARP request to given default IP address
   */
  arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */

  while (1) {
    /*
     * Proccess packets in the capture buffer
     */
    if (netdevice_rx(p) == -1) {
      break;
    }

    /*----------------------------------*
     * Other works can be inserted here *
     *----------------------------------*/

    /*
     * If key is not pressed, continue to next loop
     */
    if (!readready()) {
      continue;
    }
    /*
     * If user pressed enter, exit the program
     */
    if ((key = fgetc(stdin)) == '\n') {
      break;
    }
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
      break;
    }
    if ((ip = retrieve_ip_addr(buf)) == 0) {
      printf("Invalid IP (Enter to exit)\n");
    } else {
      arp_request(p, (unsigned char *)&ip);
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
  netdevice_t *p;

  /*
   * Get the device name of capture interface
   */
  if (argc == 2) {
    strcpy(devname, argv[1]);
  } else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
    return -1;
  }

  /*
   * Open the specified interface
   */
  if ((p = netdevice_open(devname, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open capture interface\n\t%s\n", errbuf);
    return -1;
  }
  printf("Capturing packets on interface %s\n", devname);

  /*
   * Register the packet handler callback of specific protocol
   */
  netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);

  main_proc(p);

  /*
   * Clean up the resources
   */
  netdevice_close(p);
  return 0;
}
