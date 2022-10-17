#include <pcap/pcap.h>
#include <stdlib.h>

// For libpcap that doesn't support WinPcap
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i = 0;
  char errbuf[PCAP_ERRBUF_SIZE];

  /* Retrieve the device list from the local machine */
#if HAVE_REMOTE
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */,
                          &alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
    exit(1);
  }
#else
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }
#endif

  /* Print the list */
  for (d = alldevs; d != NULL; d = d->next) {
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

  /* We don't need any more the device list. Free it */
  pcap_freealldevs(alldevs);
  return 0;
}
