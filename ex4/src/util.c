#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "common.h"

/******
 ****** Utilities
 ******/

#if (FG_NATIVE_CYGWIN == 1)
#include <sys/select.h>

/*
 * readready() - check whether read ready for given file descriptor
 *	. return non-negative if ready, 0 if not ready, negative on errors
 */

int
readready()
{
	fd_set		map;
	int			fd = 0; /* stdin */
	int			ret;
	struct timeval	_zerotimeval = {0, 0};

	do {
		FD_ZERO(&map);
		FD_SET(fd, &map);
		ret = select(fd+1, &map, NULL, NULL, &_zerotimeval);
		if(ret >= 0)
			return ret;
	} while(errno == EINTR);
	return ret;
}

#else
int
readready()
{
	extern int _kbhit();
	return _kbhit();
}
#endif /* FG_NATIVE_CYGWIN */

/*
 * time2decstr()
 */

char *
time2decstr(time_t t)
{
	static char	buf[20+1];
	struct tm ltime;

	if(t == 0) t = time(0);
	localtime_r(&t, &ltime);
	strftime(buf, 20, "%Y/%m/%d %H:%M:%S", &ltime);
	return buf;
}

/*
 * my_inet_addr()
 */

ipaddr_t
my_inet_addr(char *ip)
{
	int				n0, n1, n2, n3;
	ipaddr_t		ret;
	uint8_t	*p;

	if(sscanf(ip, "%d.%d.%d.%d", &n0, &n1, &n2, &n3) < 4) return 0;
	p = (uint8_t *) &ret;
	p[0] = n0; p[1] = n1; p[2] = n2; p[3] = n3;
	return ret;
}

/*
 * ip_addrstr()
 */

char *
ip_addrstr(uint8_t *ip, char *buf)
{
	static char	ipbuf[BUFLEN_IP];

	if(buf == NULL) buf = ipbuf;
	sprintf(buf, "%d.%d.%d.%d",
		(int) ip[0], (int) ip[1], (int) ip[2], (int) ip[3]);
	return buf;
}

/*
 * eth_macaddr()
 */

char *
eth_macaddr(const uint8_t *a, char *buf)
{
	static char	ethbuf[BUFLEN_ETH];

	if(buf == NULL) buf = ethbuf;
	sprintf(buf, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		a[0], a[1], a[2], a[3], a[4], a[5]);
	return buf;
}

/*
 * print_ip()
 */
 
void
print_ip(uint8_t *ip, char *endmsg)
{
	int	i;

	for(i = 0; i < 4; i++) {
		if(i != 0) printf(".");
		printf("%d", (int) ip[i]);
	}
	if(endmsg != NULL) printf("%s", endmsg);
}

/*
 * print_data()
 */
 
void
print_data(const uint8_t *data, int len)
{
	int		i;

	for(i=0; (i < len && i < MAX_DUMP_LEN ) ; i++) {
		printf("%.2x ", data[i]);
		if(((i+1) % MAX_LINE_LEN) == 0) printf("\n");
	}
	if((i % MAX_LINE_LEN) != 0) printf("\n");
}

/*
 * trimright()
 */

char *
trimright(char *str)
{
	int		len = strlen(str);
	
	while(len > 0) {
		if(strchr("\r\n\t ", *(str+len-1)) == NULL)
			break;
		len = len - 1;
		*(str + len) = '\0';
	}
	return str;
}

/*
 * swap16()
 */

uint16_t
swap16(uint16_t val)
{
	char	*p, p0;

	p = (char *) &val;
	p0 = p[0];
	p[0] = p[1];
	p[1] = p0;
	return val;
}

uint32_t
swap32(uint32_t val)
{
	char	*p, p0, p1;

	p = (char *) &val;
	p0 = p[0];
	p1 = p[1];
	p[0] = p[3];
	p[1] = p[2];
	p[2] = p1;
	p[3] = p0;
	return val;
}

/*
 * checksum()
 */

uint16_t
checksum(char *ptr, int len)
{
	uint16_t	*buf = (uint16_t *) ptr;
	int		nwords = len / 2;
	uint32_t	sum;

	for(sum = 0; nwords > 0; nwords--)
		sum += swap16(*buf++);
	if((len & 0x1) != 0) { /* odd length */
		sum += swap16(*((uint8_t *) buf));
	}		
	sum = (sum >> 16) + (sum & 0xffff);
	return swap16((uint16_t)(~sum));
}
