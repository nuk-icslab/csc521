#include <stdio.h>
#include <stdlib.h>
/* #include <windows.h> */

#include <pcap/pcap.h>

#include "common.h"
#include "arp.h"
#include "icmp.h"
#include "dns.h"

void
pkt_main(pcap_t *fp, struct pcap_pkthdr	*header, uint8_t *pkt_data)
{
    myeth_t			*pkt = (myeth_t *) pkt_data;
	int				pktlen = header->caplen;
#if(DEBUG_PACKET == 1)
    char			addrsrc[BUFLEN_ETH], addrdst[BUFLEN_ETH];
#endif /* DEBUG_PACKET */

#if(DEBUG_PACKET == 1)
			/* print pkt timestamp and pkt len */
   	printf("*%s %s=>%s (Type=%.2x%.2x/Len=%ld)\n",
	time2decstr(header->ts.tv_sec),
	eth_macaddr(pkt_data + 6, addrsrc),
	eth_macaddr(pkt_data, addrdst),
	pkt_data[12], pkt_data[13], header->len);
#endif /* DEBUG_PACKET */
#if(DEBUG_PACKET_DUMP == 1)	     
	print_data(pkt_data, pktlen);
#endif /* DEBUG_PACKET_DUMP */
	switch(pkt->eth_type) {
	case ETH_ARP:
		arp_main(fp, (uint8_t *) pkt_data, pktlen);
		break;
	case ETH_IP:
		ip_main(fp, (uint8_t *) pkt_data, pktlen);
		break;
	}
}

int
pkt_loop(pcap_t *fp, int loop)
{
	int					i, res;
	struct pcap_pkthdr	*header;
	const uint8_t		*pkt_data;
	
	/*---- Read the packets */
	for(i = 0; loop == 0 || i < loop; i++) {
		if((res = pcap_next_ex(fp, &header, &pkt_data)) == -1) {
        	fprintf(stderr, "Error reading the packets: %s\n",
			pcap_geterr(fp));
			return -1;
		}
		if(res > 0) pkt_main(fp, header, (uint8_t *) pkt_data);

		if(readready() != 0) break;
	}

	/*---- exit */
	return 0;	/* expired */
}

/******
 ****** main_proc() - the main thread
 ******/

int
main_proc(pcap_t *fp)
{
    struct pcap_pkthdr	*header;
    const uint8_t	*pkt_data;
    char		buf[MAX_LINEBUF];
    ipaddr_t		ip;	
    int			res, key;


#if(FG_ARP_SEND_REQUEST == 1)
	arp_request(fp, NULL);
#endif /* FG_ARP_REQUEST */
#if(FG_ICMP_SEND_REQUEST == 1)
	icmp_ping(fp, NULL, NULL);
#endif /* FG_ICMP_SEND_REQUEST */

    /* Read the packets */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0) {
		/* packet received? */
		if(res > 0) pkt_main(fp, header, (uint8_t *) pkt_data);
		
		/* key pressed? */
		if(!readready()) continue;
		if((key = fgetc(stdin)) == '\n') break;
		ungetc(key, stdin);
		if(fgets(buf, MAX_LINEBUF, stdin) == NULL) break;
		trimright(buf);
		if((ip = my_inet_addr(buf)) != 0
		  || (ip = resolve(fp, buf)) != 0) {
#if(FG_DNS_DO_PING == 1)
			icmp_ping(fp, NULL, (uint8_t *) &ip);
#else
			printf("%s\t%s\n", buf, ip_addrstr(ip, NULL));
#endif /* FG_DNS_DO_PING */
		} else {
			printf("Invalid IP (Enter to exit)\n");
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
	unsigned int		inum, i = 0;
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
                        100			/* read timeout (msec).
                           			   This option may be ignored in some OSes */,
                        errbuf		/* error buf */ )
                        ) == NULL) {
        	fprintf(stderr,"\nError opening source: %s\n", errbuf);
		return -1;
	}

	/*----- Put the capture device into non-blocking mode */
	if(pcap_setnonblock(fp, 1, errbuf)!=0){
		fprintf(stderr,"\nCan't set non-blocking mode: %s\n", errbuf);
	}

	main_proc(fp);

	/*----- done */
	pcap_close(fp);
	return 0;
}
