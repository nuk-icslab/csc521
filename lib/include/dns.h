#ifndef __DNS_H__
#define __DNS_H__

#include "ip.h"
#include "netdevice.h"
#include "udp.h"
#include "util.h"

/***
 ***	DNS
 ***/

/*
 * Control flags
 */
#ifndef DEBUG_DNS
#define DEBUG_DNS 0
#endif  // DEBUG_DNS
#ifndef DEBUG_DNS_DUMP
#define DEBUG_DNS_DUMP 0
#endif  // DEBUG_DNS_DUMP

/*====================*
 ***** Parameters *****
 *====================*/
#define MAX_DNS_TRY 3
#define DEF_DNS_SLEEP 2 /* seconds */
#define DEF_DNS_UDP_SRCPORT 0x3456
#define DEF_DNS_ID 0x5501
extern uint8_t defdnsip[IPV4_ADDR_LEN];

/*============================*
 ***** Protocol Constants *****
 *============================*/

#define UDP_PORT_DNS 53

#define DOMSIZE 1024 /* maximum domain message size to mess with */
/*
 *  flag masks for the flags field of the DOMAIN header
 */

#define DFG_QR 0x8000     /* query = 0, response = 1 */
#define DFG_OPCODE 0x7100 /* opcode, see below */
#define DFG_AA 0x0400     /* Authoritative answer */
#define DFG_TC 0x0200     /* Truncation, response was cut off at 512 */
#define DFG_RD 0x0100     /* Recursion desired */
#define DFG_RA 0x0080     /* Recursion available */
#define DFG_RCODE 0x000F  /* response code, see below */

/* opcode possible values: */
#define DOP_QUERY 0 /* a standard query */
#define DOP_IQ 1    /* an inverse query */
#define DOP_CQM 2   /* a completion query, multiple reply */
#define DOP_CQU 3   /* a completion query, single reply */
                    /* the rest reserved for future */

/* legal response codes: */
#define DRES_OK 0    /* okay response */
#define DRES_FORM 1  /* format error */
#define DRES_FAIL 2  /* their problem, server failed */
#define DRES_NAME 3  /* name error, we know name doesn't exist */
#define DRES_NOPE 4  /* no can do request */
#define DRES_NOWAY 5 /* name server refusing to do request */

/* misc definition */
#define DTYPE_A 1     /* host address resource record (RR) */
#define DTYPE_CNAME 5 /* The canonical name for an alias*/
#define DTYPE_PTR 12  /* a domain name ptr */

#define DCLASS_IN 1     /* ARPA internet class */
#define DCLASS_WILD 255 /* wildcard for several of classifications */

/*=========================*
 ***** Protocol Format *****
 *=========================*/
/*
 *  Header for the DOMAIN queries
 *  ALL OF THESE ARE BYTE SWAPPED QUANTITIES!
 *  We are the poor slobs who are incompatible with the world's byte order
 */

typedef struct {
  word ident,         /* unique identifier */
      flags, qdcount, /* question section, # of entries */
      ancount,        /* answers, how many */
      nscount,        /* count of name server RRs */
      arcount;        /* number of "additional" records */
} dnshead_t;

/*
 *  a resource record is made up of a compressed domain name followed by
 *  this structure.  All of these ints need to be byteswapped before use.
 */

struct rrpart {
  word rtype;          /* resource record type = DTYPEA */
  word rclass;         /* RR class = DIN */
  longword ttl;        /* time-to-live, changed to 32 bits */
  word rdlength;       /* length of next field */
  byte rdata[DOMSIZE]; /* data field */
};

/*
 * The type and class part of an question entry
 */
struct qpart {
  word qtype;
  word qclass;
};

/*
 *  data for domain name lookup
 */
typedef struct {
  dnshead_t header;
  byte payload[DOMSIZE];
} mydns_t;

/*========================*
 ***** Public Methods *****
 *========================*/
extern void dns_main(netdevice_t *p, myip_hdr_t *ip_hdr, uint8_t *pkt, int len);
extern ipaddr_t resolve(netdevice_t *p, char *name);

#endif /* __DNS_H__ */
