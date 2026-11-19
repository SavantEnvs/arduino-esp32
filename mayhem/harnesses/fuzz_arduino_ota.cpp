// Fuzz target: libraries/ArduinoOTA — the network OTA protocol a sketch with
// ArduinoOTA.begin()/handle() answers on UDP 3232 (anyone on the LAN can send
// an invitation), then the firmware stream it pulls over TCP.
//
// Input: byte 0 = flags (bit 0: the sketch set an OTA password, so the
// AUTH challenge/response path with PBKDF2-HMAC-SHA256 runs); the rest is a
// list of segments separated by the line "\n--NEXT--\n". A segment starting
// with 'T' is the payload of the next TCP connection the device opens back to
// the invitation's sender (the firmware upload); any other segment is one UDP
// datagram. handle() is called once per datagram (plus once more so a pending
// OTA_RUNUPDATE runs), exactly like a sketch's loop(): the upstream _onRx()
// parses "<cmd> <port> <size> <md5>\n" / "200 <cnonce> <response>\n" and
// _runUpdate() streams the TCP bytes into the (host, RAM) Update sink.
#include <Arduino.h>
#include <ArduinoOTA.h>
#include "NetworkClient.h"

void host_udp_queue_reset();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const uint8_t flags = data[0];
  data++; size--;
  host_reset_clock();
  host_net_reset();
  host_udp_queue_reset();
  int datagrams = 0;
  static const char kSep[] = "\n--NEXT--\n";
  const size_t sepLen = sizeof(kSep) - 1;
  const uint8_t *p = data, *end = data + size;
  for (;;) {
    const uint8_t *q = std::search(p, end, kSep, kSep + sepLen);
    if (q > p && *p == 'T') {
      host_net_set_incoming(p + 1, (size_t)(q - p - 1));
    } else {
      host_udp_queue(p, (size_t)(q - p));
      datagrams++;
    }
    if (q == end) break;
    p = q + sepLen;
  }
  {
    ArduinoOTAClass ota(&Update);
    ota.setRebootOnSuccess(false);
    ota.setMdnsEnabled(false);
    ota.setTimeout(50);
    ota.setHostname("esp32-fuzz");
    if (flags & 1) ota.setPassword("admin");
    ota.onError([](ota_error_t) {});
    ota.onProgress([](unsigned int, unsigned int) {});
    ota.begin();
    for (int i = 0; i <= datagrams && i < 16; i++) ota.handle();
    ota.end();
  }
  host_net_reset();
  host_udp_queue_reset();
  return 0;
}
