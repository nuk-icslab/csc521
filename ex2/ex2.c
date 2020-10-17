#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>

#include "common.h"
#include "arp.h"

/******
 ****** main_proc() - the main thread
 ******/

int
main_proc(pcap_t *fp)
{
    struct pcap_pkthdr	*header;
    myeth_t				*pkt;
    const u_char		*pkt_data;
    char				buf[MAX_LINEBUF];
    ipaddr_t			ip;	
    int					res, key, pktlen;
#if(DEBUG_PACKET == 1)
    char			addrsrc[BUFLEN_ETH], addrdst[BUFLEN_ETH];
#endif /* DEBUG_PACKET */

#if(FG_ARP_SEND_REQUEST == 1)
	arp_request(fp, NULL);
#endif /* FG_ARP_REQUEST */

    /* Read the packets */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0) {
		/* packet received? */
		if(res > 0) {
#if(DEBUG_PACKET == 1)
			/* print pkt timestamp and pkt len */
        printf("*%s %s=>%s (Type=%.2x%.2x/Len=%d)\n",
					time2decstr(header->ts.tv_sec),
					eth_macaddr(pkt_data + 6, addrsrc),
					eth_macaddr(pkt_data, addrdst),
					pkt_data[12], pkt_data[13], header->len);
#endif /* DEBUG_PACKET */
			pkt = (myeth_t *) pkt_data;
			pktlen = header->caplen;
#if(DEBUG_PACKET_DUMP == 1)	     
			print_data(pkt_data, pktlen);
#endif /* DEBUG_PACKET_DUMP */
			switch(pkt->eth_type) {
			case ETH_ARP:
#if(DEBUG_PACKET_DUMP == 0 && DEBUG_ARP_DUMP == 1)
				print_data(pkt_data, pktlen);
#endif /* DEBUG_ARP_DUMP */
				arp_main(fp, (unsigned char *) pkt_data, pktlen);
				break;
			}
		}
		
		/* key pressed? */
		if(!readready()) continue;
		if((key = fgetc(stdin)) == '\n') break;
		ungetc(key, stdin);
		if(fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
		if((ip = my_inet_addr(buf)) == 0) {
			printf("Invalid IP (Enter to exit)\n");
		} else {
			arp_request(fp, (unsigned char *) &ip);
		}
	}
    	
    if(res == -1) {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}

/****
 ****	MAIN ENTRY
 ****/

char *
mypcap_getdevice(int defn)
{
	pcap_if_t	*alldevs, *d;
	u_int		inum, i = 0;
	char		errbuf[PCAP_ERRBUF_SIZE];
	char		buf[MAX_LINEBUF];
	
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return NULL;
	}

	if(defn > 0) {
		inum = defn;
		for(d=alldevs; d; d=d->next, ++i);
	} else {
	    /* Print the list */
	    printf("Device list:\n");
		for(d=alldevs; d; d=d->next) {
			printf("%d. %s\n    ", ++i, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
        
		if (i==0) {
			fprintf(stderr,"No interfaces found! Exiting.\n");
			return NULL;
		}
	
		printf("Enter the interface number (1-%d):",i);
		fgets(buf, MAX_LINEBUF, stdin);
		sscanf(buf, "%d", &inum);
	}

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return NULL;
	}
        
	/* Jump to the selected adapter */
	for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	return d->name;
}

int
main(int argc, char *argv[])
{
	char	*devname, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*fp;
	//DWORD	ThreadId;
	//HANDLE	ThreadHandle;

	/*----- Get device name */
	if (argc == 2) {
		devname = argv[1];
	} else if((devname = mypcap_getdevice(0)) == NULL) {
		return -1;
	}

	/*----- open the specified adapter/interface */
	if((fp= pcap_open_live(devname,
                        MAX_CAP_LEN	/* snaplen*/,
                        PCAP_OPENFLAG_PROMISCUOUS	/*flags*/,
                        100			/* read timeout (msec) */,
                        errbuf		/* error buf */ )
                        ) == NULL) {
        	fprintf(stderr,"\nError opening source: %s\n", errbuf);
		return -1;
	}

	main_proc(fp);

	/*----- done */
	pcap_close(fp);
	return 0;
}
