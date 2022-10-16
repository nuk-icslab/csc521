#include <stdint.h>

/*
 * The MAC address of your interface
 */
uint8_t myethaddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
 * The IP address of your interface
 */
uint8_t myipaddr[] = {192, 168, 0, 10};

/*
 * The default IP address to send ARP requests to
 */
uint8_t defarpip[] = {192, 168, 0, 1};