#include <string.h>
#include "common.h"

#define MAX_ARPIP_N		8

typedef struct {
	ipaddr_t		ip;
	uint8_t	eth[6];
} ipethaddr_t;

ipethaddr_t		arptable[MAX_ARPIP_N];
int			arptable_n = 0;

/*
 * arptable_existed()
 */

uint8_t *
arptable_existed(uint8_t *ipaddr)
{
	int		i;
	ipaddr_t		ip;

	ip = *((ipaddr_t *) ipaddr);
	for(i = 0; i < MAX_ARPIP_N; i++)
		if(ip == arptable[i].ip) return arptable[i].eth;
	return NULL;
}

/*
 * arptable_add()
 */

void
arptable_add(uint8_t *ip, uint8_t *eth)
{
#if(DEBUG_ARPCACHE == 1)
	char		bufip[BUFLEN_IP], bufeth[BUFLEN_ETH];

	printf("ARPCache#%d: %s, %s\n", arptable_n+1,
		ip_addrstr(ip, bufip), eth_macaddr(eth, bufeth));
#endif /* DEBUG_ARPCACHE == 1 */

	arptable_n = (++arptable_n) % MAX_ARPIP_N;
	arptable[arptable_n].ip = *((ipaddr_t *) ip);
	memcpy(arptable[arptable_n].eth, eth, 6);
}
