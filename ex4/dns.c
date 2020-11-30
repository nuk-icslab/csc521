#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "dns.h"

static ipaddr_t		dns_answer = 0;

/******
 ******
 ******/

/*
 * dns_unpack() - unpack a compressed domain name received from another host
 *	. Returns the number of bytes at src which should be skipped over.
 *	. Handles pointers to continuation domain names
 *	. Includes the NULL terminator in its length count.
 */

static word
dns_unpack(char *dst, char *src, char *buf)
{
	int		i, j, retval, labellen;
	char	*savesrc;

	savesrc = src;
	retval = 0;

	while (*src) {	/* end with 0x00 */
		j = *((unsigned char *) src);

		while ((j & 0xC0) == 0xC0) {	/* pointer */
			if (!retval) retval = src - savesrc + 2;
			src++;
			src = &buf[(j & 0x3f)*256 + *((unsigned char *) src)];
			j = *((unsigned char *) src);
		}
		labellen = j & 0x3f;	/* the 1st byte is the length */
		src++;
		for (i=0; i < labellen ; i++) *dst++ = *src++;

		*dst++ = '.';
	}
	*(--dst) = '\0';	/* add terminator */
	src++;			/* account for terminator on src */

	if (!retval) retval = src-savesrc;

	return(retval);
}

/*
 * dns_extract() - extract the ip number from a response message
 *	. returns the appropriate status code and
 *		if the ip number is available, copies it into mip
 */

int
dns_extract(myudp_t *udp, unsigned char *mip)
{
	mydns_t			*qp = (mydns_t *) udp->udp_data;
	word			i, j, nans, rcode;
	struct rrpart	*rrp;
	byte			*p, space[260];
	int				dns_answer_count = 0;

	nans = swap16(qp->h.ancount);		/* number of answers */
	rcode = DFG_RCODE & swap16(qp->h.flags);	/* return code */
	if (rcode > 0) return(rcode);

	if (nans < 1 || !((swap16(qp->h.flags) & DFG_QR)))
		return (-1); /* error: no answers or response flag not set */

	/*---- question section */
	p = (byte *) &qp->x;			/* where question starts */
	i = dns_unpack(space, p, (char *) qp);	/* unpack question name */
	p += i+4;	/*  spec defines name then QTYPE + QCLASS = 4 bytes */

	/*---- answer section */
	/*	There may be several answers.
	 *	We will take the first one which has an IP number.
	 *	There may be other types of answers to support later.
	 */

	while (nans-- > 0) {		/* look at each answer */
		i = dns_unpack(space,p, (char *) qp); /* answer to unpack */
		p += i;				/* account for string */
		rrp = (struct rrpart *)p;	/* resource record here */

		if (!*p && *(p+1) == DTYPE_A && !*(p+2) && *(p+3) == DCLASS_IN) {
	    		/* correct type and class */
			setip(mip, rrp->rdata);	/* save IP # */
			dns_answer_count++;
#if(DEBUG_DNS == 1)
			printf("dns_extract(): Answer %d = ", dns_answer_count);
			print_ip((unsigned char *) mip, "\n");
#endif /* DEBUG_DNS == 1 */
			return(0);		/* successful return */
		}
		memcpy(&j, &rrp->rdlength, 2);
		p += 10+swap16(j);		/* length of rest of RR */
	}
	if (dns_answer_count != 0) return (0);
	return(-1);	/* answer not found */
}

/******
 ******
 ******/

static void
dns_qinit(mydns_t *question)
{
	question->h.flags = swap16(DFG_RD);
	question->h.qdcount = swap16(1);
	question->h.ancount = 0;
	question->h.nscount = 0;
	question->h.arcount = 0;
}

/*
 * dns_packdom() - pack a regular text string into a packed domain name
 *	. returns packeted length
 */

static int
dns_packdom(char *dst, char *src)
{
	char		*p, *q, *savedst;
	int			i, dotflag, defflag;

	p = src;
	dotflag = defflag = 0;
	savedst = dst;

	do {			/* copy whole string */
		*dst = 0;
		q = dst + 1;	/* for length */
		while (*p && (*p != '.')) {
			*q++ = *p++;
		}

		if((i = p - src) > 0x3f) return(-1);	/* too long */
		*dst = i;
		*q = 0;

		if (*p) {	/* not finished yet, update pointers */
			dotflag = 1;
			src = ++p;
			dst = q;
		}
	} while (*p);
	q++;
	return(q-savedst);	/* length of packed string */
}

/*
 * dns_sendom() - put together a domain lookup packet and send it
 *	. uses port 53, num is used as identifier
 */

static void
dns_sendom(pcap_t *fp, char *mname, longword nameserver)
{
	mydns_t		question;
	char		namebuf[DOMSIZE];
	word		i, ulen;
	byte		*psave, *p;

#if(DEBUG_DNS == 1)
	printf("dns_sendom(): %s\n", mname);
#endif /* DEBUG_DNS == 1 */

	strcpy_s(namebuf, DOMSIZE, mname);

	dns_qinit(&question);	/* initialize some flag fields */

	psave = (byte*)&(question.x);
	i = dns_packdom((byte *)&(question.x), namebuf);

	p = &(question.x[i]);
	*p++ = 0;			/* high byte of qtype */
	*p++ = DTYPE_A;		/* number is < 256, so we know high byte=0 */
	*p++ = 0;			/* high byte of qclass */
	*p++ = DCLASS_IN;	/* qtype is < 256 */

	question.h.ident = swap16(DEF_DNS_ID);
	ulen = sizeof(dnshead_t)+(p-psave);
#if(DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_UDP_DUMP == 0 && DEBUG_DNS_DUMP == 1)
	print_data((unsigned char *)&question, ulen);
#endif /* DEBUG_DNS_DUMP */
	udp_send(fp, DEF_DNS_UDP_SRCPORT, nameserver, 53, (char *) &question, ulen);
}

/*
 * resolve() - query a domain name server to get an IP number
 *	. Returns the IP of the machine record for future reference.
 *	. returns 0 if name is unresolvable right now
 */

ipaddr_t
resolve(pcap_t *fp, char *name)
{
	time_t		now, later; 
	longword	ip_address, nameserver;
	int			trycount = MAX_DNS_TRY;

	nameserver = *((longword *) defdnsip);
	dns_answer = 0;

	while(trycount-- > 0) {
		dns_sendom(fp, name, nameserver);
		now=time(NULL);
		later=now+DEF_DNS_SLEEP;
		do {
			pkt_loop(fp, 1);
			if(dns_answer != 0) {
				ip_address = dns_answer;
				dns_answer = 0;
				return( ip_address );
			}
		} while((now=time(NULL)) <= later);
	}
	return( 0);
}

/******
 ******
 ******/

void
dns_main(pcap_t *fp, myip_t *ip, myudp_t *udp, int udplen)
{
	int				i;
	ipaddr_t		ipaddr;	/* returned ip */

#if(DEBUG_DNS == 1)
	printf("dns_main(): Len=%d, ", udplen-8);
	print_ip(ip->ip_srcip, "->");
	print_ip(ip->ip_dstip, "\n");
#endif /* DEBUG_DNS == 1 */
#if(DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_UDP_DUMP == 0 && DEBUG_DNS_DUMP == 1)
		print_data((unsigned char *)udp->udp_data, udplen-8);
#endif /* DEBUG_DNS_DUMP */

    	i = dns_extract(udp, (unsigned char *) &ipaddr);
	switch (i) {
        case 0: /* we found the IP number */
		dns_answer = ipaddr;
		break;
        case 3:		/* name does not exist */
        case -1:	/* strange return code from dns_extract */
        default:	/* dunno */
#if(DEBUG_DNS == 1)
		printf("\tdns_extract() return %08lx\n", i);
		print_data(udp->udp_data, swap16(udp->udp_length));
#endif /* DEBUG_DNS == 1 */
		return;
	}
}
