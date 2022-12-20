#include <stdint.h>

uint8_t myethaddr[] = {0x8c, 0xa9, 0x82, 0xe3, 0x3c, 0xda};
uint8_t myipaddr[] = {192, 168, 88, 51};

uint8_t myrouterip[] = {192, 168, 88, 254};
uint8_t mynetmask[] = {255, 255, 255, 0};

uint8_t defarpip[] = {192, 168, 88, 254};
uint8_t defpingip[] = {140, 127, 208, 18};

uint8_t defdnsip[] = {8, 8, 8, 8};
char* defdnsquery = "csc521.csie.nuk.edu.tw";

uint16_t tcp_filter_port = 0x5678;