// Fuzz target: libraries/NetBIOS — a NetBIOS name-service query (UDP 137) from
// any host on the LAN. NetBIOS::begin("ESP32") registers its handler on the
// host AsyncUDP and the whole input is delivered to it as one datagram, so
// the upstream _onPacket() parses the question and builds the answer.
#include <Arduino.h>
#include <NetBIOS.h>
#include "AsyncUDP.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  host_udp_reset();
  {
    NetBIOS nbns;
    if (!nbns.begin("ESP32")) return 0;
    host_udp_deliver(data, size);
    nbns.end();
  }
  host_udp_reset();
  return 0;
}
