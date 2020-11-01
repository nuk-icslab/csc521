#include "common.h"

#define MAX_IP		5

ipaddr_t			iptable[MAX_IP];
int			iptable_n = 0;

int
iptable_existed(uint8_t *ip)
{
	int		i;
	ipaddr_t		*addr;

	addr = (ipaddr_t *) ip;
	for(i = 0; i < iptable_n; i++)
		if(*addr == iptable[i]) return 1;
	return 0;
}

int
iptable_add(uint8_t *ip)
{
	if(iptable_n == MAX_IP) return -1;
	iptable[iptable_n++] = *((ipaddr_t *) ip);
	return 0;
}