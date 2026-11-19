#pragma once
#include "NetworkClient.h"
#include "NetworkServer.h"
#include "NetworkUdp.h"
// IN6ADDR_ANY: the dual-stack "any" address (lwIP's ip6_addr_any).
#define IN6ADDR_ANY IPAddress(IPv6)
class HostNetworkManager {
public:
  void macAddress(uint8_t *mac) { static const uint8_t m[6] = {0x24, 0x0a, 0xc4, 0x12, 0x34, 0x56}; memcpy(mac, m, 6); }
};
extern HostNetworkManager Network;
class HostEspClass {
public:
  void restart() { abort(); }  // never reached: harnesses disable reboot-on-success
};
extern HostEspClass ESP;
