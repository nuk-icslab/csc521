#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  pcap_t *adhandle;
  int res;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct tm ltime;
  char timestr[16];
  struct pcap_pkthdr *header;
  const uint8_t *pkt_data;
  time_t local_tv_sec;

  /* Retrieve the device list on the local machine */
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }

  /* Print the list */
  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure libpcap is installed.\n");
    return -1;
  }

  printf("Enter the interface number (1-%d):", i);
  scanf("%d", &inum);

  if (inum < 1 || inum > i) {
    printf("\nInterface number out of range.\n");
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -1;
  }

  /* Jump to the selected adapter */
  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  /* Open the device */
  if ((adhandle =
           pcap_open_live(d->name,  // name of the device
                          65536,    // portion of the packet to capture.
                                  // 65536 guarantees that the whole packet will
                                  // be captured on all the link layers
                          PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                          1000,                       // read timeout
                          errbuf                      // error buffer
                          )) == NULL) {
    fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->name);

  /* At this point, we don't need any more the device list. Free it */
  pcap_freealldevs(alldevs);

  /* Retrieve the packets */
  while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
    if (res == 0) /* Timeout elapsed */
      continue;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime_r(&local_tv_sec, &ltime);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
  }

  // Release the handler
  pcap_close(adhandle);

  if (res == -1) {
    printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
    return -1;
  }

  return 0;
}