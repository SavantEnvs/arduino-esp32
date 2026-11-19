#pragma once
#include "lwip/ip_addr.h"
struct netif { struct netif *next; char name[2]; u8_t num; };
// No interfaces on the host: IPAddress::printTo's zone lookup walks an empty list.
static struct netif *const netif_list = 0;
#define netif_ip4_addr(n) ((const ip4_addr_t *)0)
#define netif_ip4_netmask(n) ((const ip4_addr_t *)0)
#define ip4_addr_get_u32(a) ((a) ? (a)->addr : 0u)
