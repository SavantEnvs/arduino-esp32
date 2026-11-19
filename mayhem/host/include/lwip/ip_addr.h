// Host stand-in for lwIP's ip_addr_t (dual-stack layout, as on the ESP32 build).
#pragma once
#include <stdint.h>
#define LWIP_IPV6_SCOPES 1
typedef uint32_t u32_t;
typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef struct ip4_addr { u32_t addr; } ip4_addr_t;
typedef struct ip6_addr { u32_t addr[4]; u8_t zone; } ip6_addr_t;
enum lwip_ip_addr_type { IPADDR_TYPE_V4 = 0U, IPADDR_TYPE_V6 = 6U, IPADDR_TYPE_ANY = 46U };
typedef struct ip_addr { union { ip6_addr_t ip6; ip4_addr_t ip4; } u_addr; u8_t type; } ip_addr_t;
#define IP6_NO_ZONE 0
