#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

int main(int argc, char **argv) {
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];
  uint8_t packet[100];
  int i;

  /* Check the validity of the command line */
  if (argc != 2) {
    printf("usage: %s interface (e.g. 'eth0')", argv[0]);
    return 1;
  }

  /* Open the output device */
  if ((fp = pcap_open_live(
           argv[1],  // name of the device
           100,  // portion of the packet to capture (only the first 100 bytes)
           PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
           1000,                       // read timeout
           errbuf                      // error buffer
           )) == NULL) {
    fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
    return 1;
  }

  /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
  packet[0] = 0x01;
  packet[1] = 0x01;
  packet[2] = 0x01;
  packet[3] = 0x01;
  packet[4] = 0x01;
  packet[5] = 0x01;

  /* set mac source to 2:2:2:2:2:2 */
  packet[6] = 0x02;
  packet[7] = 0x02;
  packet[8] = 0x02;
  packet[9] = 0x02;
  packet[10] = 0x02;
  packet[11] = 0x02;

  /* set ethernet frame type to 0x0c0d */
  packet[12] = 0x0c;
  packet[13] = 0x0d;

  /* Fill the rest of the packet */
  for (i = 14; i < 100; i++) {
    packet[i] = i % 256;
  }

  /* Send down the packet */
  if (pcap_sendpacket(fp, packet, 100 /* size */) != 0) {
    fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
    return 1;
  }

  pcap_close(fp);

  return 0;
}
