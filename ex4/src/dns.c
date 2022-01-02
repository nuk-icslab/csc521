#include "dns.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static ipaddr_t dns_answer = 0;

/*
 * dns_unpack() - unpack a compressed domain name received from another host
 * Returns the number of bytes at src which should be skipped over.
 * Handles pointers to continuation domain names
 * Includes the NULL terminator in its length count.
 */
static word dns_unpack(byte *dst, byte *src, byte *msg) {
  enum { ST_LEN, ST_LABEL } state = ST_LEN;
  unsigned int comp_len = 0, len, offset;
  byte *c;

#if (DEBUG_DNS == 1)
  printf("dns_unpack(): ");
#endif /* DEBUG_DNS == 1 */

  for (c = src; *c; c++) { /* end with 0x00 */
    switch (state) {
      case ST_LEN:
        if ((*c & 0xc0) != 0xc0) {
          len = (*c & 0x3f) - 1; /* The first byte is the length */
          state = ST_LABEL;
        } else {
          if (!comp_len) comp_len = c - src + sizeof(word);
          offset = swap16(*(word *)c) & 0x3fff;
#if (DEBUG_DNS == 1)
          printf("(%d) ", offset);
#endif /* DEBUG_DNS == 1 */
          c = &msg[offset] - 1;
        }
        break;
      case ST_LABEL:
#if (DEBUG_DNS == 1)
        printf("%c", *c);
#endif /* DEBUG_DNS == 1 */
        *dst++ = *c;
        if (len > 0) {
          len--;
        } else {
          *dst++ = '.';
          state = ST_LEN;
#if (DEBUG_DNS == 1)
          printf(" ");
#endif /* DEBUG_DNS == 1 */
        }
        break;
    }
  }
#if (DEBUG_DNS == 1)
  printf("\n");
#endif /* DEBUG_DNS == 1 */

  *dst = '\0'; /* add terminator */

  return comp_len ? comp_len : (c + 1) - src;
}

/*
 * dns_extract() - extract the ip number from a response message
 * returns the appropriate status code and
 * if the ip number is available, copies it into mip
 */
static int dns_extract(uint8_t *pkt, uint8_t *mip) {
  mydns_t *qp = (mydns_t *)pkt;
  word domlen, nans, rcode;
  struct rrpart *rrp;
  byte *p, name[DOMSIZE];
  int dns_answer_count = 0;

  rcode = DFG_RCODE & swap16(qp->header.flags); /* return code */
  if (rcode > 0) return (rcode);

  nans = swap16(qp->header.ancount); /* number of answers */
  if (nans < 1 || !(swap16(qp->header.flags) & DFG_QR))
    return (-1); /* error: no answers or response flag not set */

  /*---- question section */
  p = (byte *)&qp->payload;          /* where question starts */
  domlen = dns_unpack(name, p, pkt); /* unpack question name */
  printf("dns_extract(): [Question] %s\n", name);
  p += domlen + sizeof(struct qpart);

  /*---- answer section */
  /*	There may be several answers.
   *	We will take the last one which has an IP number.
   *	There may be other types of answers to support later.
   */
  while (nans-- > 0) {                 /* look at each answer */
    domlen = dns_unpack(name, p, pkt); /* answer to unpack */
    p += domlen;                       /* account for string */
    rrp = (struct rrpart *)p;          /* resource record here */

    if (swap16(rrp->rclass) == DCLASS_IN) {
      switch (swap16(rrp->rtype)) {
        case DTYPE_A:
          SET_IP(mip, rrp->rdata); /* save IP # */
          dns_answer_count++;
#if (DEBUG_DNS == 1)
          printf("dns_extract(): [Answer %d] %s IN A ", dns_answer_count, name);
          print_ip((uint8_t *)mip, "\n");
#endif /* DEBUG_DNS == 1 */
          break;
        case DTYPE_CNAME:
#if (DEBUG_DNS == 1)
          byte cname[DOMSIZE];
          dns_unpack(cname, rrp->rdata, pkt);
          printf("dns_extract(): [Answer %d] %s IN CNAME %s\n",
                 dns_answer_count, name, cname);
#endif /* DEBUG_DNS == 1 */
          break;
      }
    }
    p += ((uint8_t *)&(rrp->rdata) - (uint8_t *)rrp) + /* length of rrpart */
         swap16(rrp->rdlength); /* length of rest of RR */
  }
  if (dns_answer_count != 0) return (0);
  return (-1); /* answer not found */
}

/*
 * dns_qinit() - Initialize the question section
 */
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
static int dns_packdom(byte *dst, char *src) {
  byte *h, *d;
  const char delim = '.';

  strncat(src, &delim, 1);

#if (DEBUG_DNS == 1)
  printf("dns_packdom(): ");
#endif /* DEBUG_DNS == 1 */

  for (h = dst, d = h + 1; *src; src++) {
    if (*src != delim) {
      *d++ = (byte)*src; /* Copy the character to the destination */
    } else {
      *h = d - (h + 1);           /* Fill the length of label to the header */
      if (*h > 0x3f) return (-1); /* If the length is too long, return error*/

#if (DEBUG_DNS == 1)
      printf("%d %.*s ", *h, *h, h + 1);
#endif /* DEBUG_DNS == 1 */

      h = d, d = h + 1; /*Update the pointers*/
    }
  }
  *h = '\0'; /* Append terminator to the end */

#if (DEBUG_DNS == 1)
  printf("%d\n", *h);
#endif /* DEBUG_DNS == 1 */

  return (d - dst); /* Length of packed string */
}

/*
 * dns_sendom() - put together a domain lookup packet and send it
 *	. uses port 53, num is used as identifier
 */
static void dns_sendom(mypcap_t *p, char *mname, uint8_t *nameserver) {
  mydns_t question;
  struct qpart *question_part;
  char namebuf[DOMSIZE];
  word domlen, ulen;

#if (DEBUG_DNS == 1)
  printf("dns_sendom(): %s\n", mname);
#endif /* DEBUG_DNS == 1 */

  strcpy(namebuf, mname);

  dns_qinit(&question); /* initialize some flag fields */
  question.header.ident = swap16(DEF_DNS_ID);

  domlen = dns_packdom(question.payload, namebuf);
  question_part = (struct qpart *)(question.payload + domlen);
  question_part->qtype = swap16(DTYPE_A);
  question_part->qclass = swap16(DCLASS_IN);

  ulen = sizeof(dnshead_t) + domlen + sizeof(struct qpart);
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

/*
 * dns_main() - The main procedure to process incoming DNS message
 */
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
    case 3: /* name does not exist */
#if (DEBUG_DNS == 1)
      printf("\tdns_extract() returnd that domain name not existed(%d)\n", i);
#endif /* DEBUG_DNS == 1 */
      break;
    case -1: /* strange return code from dns_extract */
    default: /* dunno */
#if (DEBUG_DNS == 1)
      printf("\tdns_extract() return %08x\n", i);
      print_data(pkt, len);
#endif /* DEBUG_DNS == 1 */
      return;
  }
}
