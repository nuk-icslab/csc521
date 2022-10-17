#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>

struct list_head {
  struct list_head *next, *prev;
};

typedef uint32_t ipaddr_t;
typedef uint8_t byte;
typedef uint16_t word;
typedef uint32_t longword;

#endif /* __TYPES_H__ */