#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arp.h"
#include "common.h"
#include "mypcap.h"

/******
 ****** main_proc() - the main thread
 ******/

int main_proc(mypcap_t *p) {
  int key;
  char buf[MAX_LINEBUF];
  ipaddr_t ip;

#if (FG_ARP_SEND_REQUEST == 1)
  arp_request(p, NULL);
#endif /* FG_ARP_REQUEST */

  while (1) {
    if (mypcap_proc(p) == -1) {
      break;
    }
    /* key pressed? */
    if (!readready()) {
      continue;
    }
    if ((key = fgetc(stdin)) == '\n') {
      break;
    }
    ungetc(key, stdin);
    if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
      break;
    }
    if ((ip = my_inet_addr(buf)) == 0) {
      printf("Invalid IP (Enter to exit)\n");
    } else {
      arp_request(p, (unsigned char *)&ip);
    }
  }

  return 0;
}

/****
 **** MAIN ENTRY
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

  main_proc(p);

  /*
   * Clean up the resources
   */
  mypcap_close(p);
  return 0;
}
