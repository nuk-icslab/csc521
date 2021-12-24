#include "dns.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static ipaddr_t dns_answer = 0;

/*
 * dns_unpack() - unpack a compressed domain name received from another host
 *	. Returns the number of bytes at src which should be skipped over.
 *	. Handles pointers to continuation domain names
 *	. Includes the NULL terminator in its length count.
 */

static word dns_unpack(byte *dst, byte *src, byte *buf) {
  int i, j, retval, labellen;
  byte *savesrc;

  savesrc = src;
  retval = 0;

  while (*src) { /* end with 0x00 */
    j = *((uint8_t *)src);

    while ((j & 0xC0) == 0xC0) { /* pointer */
      if (!retval) retval = src - savesrc + 2;
      src++;
      src = &buf[(j & 0x3f) * 256 + *((uint8_t *)src)];
      j = *((uint8_t *)src);
    }
    labellen = j & 0x3f; /* the 1st byte is the length */
    src++;
    for (i = 0; i < labellen; i++) *dst++ = *src++;

    *dst++ = '.';
  }
  *(--dst) = '\0'; /* add terminator */
  src++;           /* account for terminator on src */

  if (!retval) retval = src - savesrc;

  return (retval);
}

/*
 * dns_extract() - extract the ip number from a response message
 * returns the appropriate status code and
 * if the ip number is available, copies it into mip
 */

static int dns_extract(uint8_t *pkt, uint8_t *mip) {
  mydns_t *qp = (mydns_t *)pkt;
  word i, j, nans, rcode;
  struct rrpart *rrp;
  byte *p, space[260];
  int dns_answer_count = 0;

  nans = swap16(qp->header.ancount);            /* number of answers */
  rcode = DFG_RCODE & swap16(qp->header.flags); /* return code */
  if (rcode > 0) return (rcode);

  if (nans < 1 || !((swap16(qp->header.flags) & DFG_QR)))
    return (-1); /* error: no answers or response flag not set */

  /*---- question section */
  p = (byte *)&qp->payload;             /* where question starts */
  i = dns_unpack(space, p, (byte *)qp); /* unpack question name */
  p += i + 4; /*  spec defines name then QTYPE + QCLASS = 4 bytes */

  /*---- answer section */
  /*	There may be several answers.
   *	We will take the first one which has an IP number.
   *	There may be other types of answers to support later.
   */

  while (nans-- > 0) {                    /* look at each answer */
    i = dns_unpack(space, p, (byte *)qp); /* answer to unpack */
    p += i;                               /* account for string */
    rrp = (struct rrpart *)p;             /* resource record here */

    if (!*p && *(p + 1) == DTYPE_A && !*(p + 2) && *(p + 3) == DCLASS_IN) {
      /* correct type and class */
      SET_IP(mip, rrp->rdata); /* save IP # */
      dns_answer_count++;
#if (DEBUG_DNS == 1)
      printf("dns_extract(): Answer %d = ", dns_answer_count);
      print_ip((uint8_t *)mip, "\n");
#endif            /* DEBUG_DNS == 1 */
      return (0); /* successful return */
    }
    memcpy(&j, &rrp->rdlength, 2);
    p += 10 + swap16(j); /* length of rest of RR */
  }
  if (dns_answer_count != 0) return (0);
  return (-1); /* answer not found */
}

/******
 ******
 ******/

static void dns_qinit(mydns_t *question) {
  question->header.flags = swap16(DFG_RD);
  question->header.qdcount = swap16(1);
  question->header.ancount = 0;
  question->header.nscount = 0;
  question->header.arcount = 0;
}

/*
 * dns_packdom() - pack a regular text string into a packed domain name
 * Returns packeted length
 */

static int dns_packdom(byte *dst, byte *src) {
  byte *p, *q, *savedst;
  int i;

  p = src;
  savedst = dst;

  do {
    // Reserve the space for length storage.
    *dst = 0;
    q = dst + 1;

    // Copy the rest of string to dst until dot symbol.
    while (*p && (*p != '.')) {
      *q++ = *p++;
    }

    // Calculate the length
    i = p - src;

    // If the length is too long, return error.
    if (i > 63) return (-1);

    // Copy the length to the reserved space.
    *dst = i;
    *q = 0;

    // If not finished yet, update pointers.
    if (*p) {
      src = ++p;
      dst = q;
    }
  } while (*p);
  q++;
  return (q - savedst); /* length of packed string */
}

/*
 * dns_sendom() - put together a domain lookup packet and send it
 *	. uses port 53, num is used as identifier
 */

static void dns_sendom(mypcap_t *p, char *mname, uint8_t *nameserver) {
  mydns_t question;
  byte namebuf[DOMSIZE];
  word i, ulen;
  byte *psave, *payload;

#if (DEBUG_DNS == 1)
  printf("dns_sendom(): %s\n", mname);
#endif /* DEBUG_DNS == 1 */

  strcpy((char *)namebuf, mname);

  dns_qinit(&question); /* initialize some flag fields */

  psave = (byte *)&(question.payload);
  i = dns_packdom(psave, namebuf);

  payload = &(question.payload[i]);
  *payload++ = 0;         /* high byte of qtype */
  *payload++ = DTYPE_A;   /* number is < 256, so we know high byte=0 */
  *payload++ = 0;         /* high byte of qclass */
  *payload++ = DCLASS_IN; /* qtype is < 256 */

  question.header.ident = swap16(DEF_DNS_ID);
  ulen = sizeof(dnshead_t) + (payload - psave);
#if (DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_UDP_DUMP == 0 && \
     DEBUG_DNS_DUMP == 1)
  print_data((uint8_t *)&question, ulen);
#endif /* DEBUG_DNS_DUMP */

  myudp_param_t udp_param;
  udp_param.dstport = UDP_PORT_DNS;
  udp_param.srcport = DEF_DNS_UDP_SRCPORT;
  COPY_IPV4_ADDR(udp_param.ip.dstip, nameserver);

  udp_send(p, udp_param, (uint8_t *)&question, ulen);
}

/*
 * resolve() - query a domain name server to get an IP number
 * Returns the IP of the machine record for future reference.
 * Returns 0 if name is unresolvable right now
 */

ipaddr_t resolve(mypcap_t *p, char *name) {
  time_t now, later;
  longword ip_address;
  int trycount = MAX_DNS_TRY;

  dns_answer = 0;

  while (trycount-- > 0) {
    dns_sendom(p, name, defdnsip);
    now = time(NULL);
    later = now + DEF_DNS_SLEEP;
    do {
      if (mypcap_proc(p) == -1) {
        break;
      }
      if (dns_answer != 0) {
        ip_address = dns_answer;
        dns_answer = 0;
        return (ip_address);
      }
    } while ((now = time(NULL)) <= later);
  }
  return (0);
}

/******
 ******
 ******/

void dns_main(mypcap_t *p, myip_hdr_t *ip_hdr, uint8_t *pkt, int len) {
  int i;
  ipaddr_t ipaddr; /* returned ip */

  myudp_hdr_t *udp_hdr = (myudp_hdr_t *)pkt;
  pkt += sizeof(myudp_hdr_t);
  len -= sizeof(myudp_hdr_t);

  assert(swap16(udp_hdr->length) == len + sizeof(myudp_hdr_t));

#if (DEBUG_DNS == 1)
  printf("dns_main(): Len=%d, ", len);
  print_ip(ip_hdr->srcip, "->");
  print_ip(ip_hdr->dstip, "\n");
#endif /* DEBUG_DNS == 1 */
#if (DEBUG_PACKET_DUMP == 0 && DEBUG_IP_DUMP == 0 && DEBUG_UDP_DUMP == 0 && \
     DEBUG_DNS_DUMP == 1)
  print_data(pkt, len);
#endif /* DEBUG_DNS_DUMP */

  i = dns_extract(pkt, (uint8_t *)&ipaddr);
  switch (i) {
    case 0: /* we found the IP number */
      dns_answer = ipaddr;
      break;
    case 3:  /* name does not exist */
    case -1: /* strange return code from dns_extract */
    default: /* dunno */
#if (DEBUG_DNS == 1)
      printf("\tdns_extract() return %08x\n", i);
      print_data(pkt, len);
#endif /* DEBUG_DNS == 1 */
      return;
  }
}
