// Fuzz target: libraries/DNSServer — a DNS query received by a captive-portal
// sketch (any client on the soft-AP can send it).
//
// Input: byte 0 selects the server configuration (wildcard "*" vs a fixed
// domain with a "www." prefix, error reply code, TTL); the rest is the UDP
// datagram. DNSServer::start() registers its handler on the host AsyncUDP and
// the datagram is delivered to it exactly as AsyncUDP's receive callback does:
// header/question parsing, domain-name extraction and matching, and the
// replyWithIP / replyWithCustomCode / replyWithNoAnsw builders all run.
#include <Arduino.h>
#include <DNSServer.h>
#include "AsyncUDP.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const uint8_t cfg = data[0];
  host_udp_reset();
  {
    DNSServer dns;
    static const DNSReplyCode codes[] = {DNSReplyCode::NoError, DNSReplyCode::FormError, DNSReplyCode::ServerFailure,
                                         DNSReplyCode::NonExistentDomain, DNSReplyCode::NotImplemented, DNSReplyCode::Refused};
    dns.setErrorReplyCode(codes[(cfg >> 1) % 6]);
    dns.setTTL((cfg & 0x10) ? 0 : 60);
    const String domain = (cfg & 1) ? String("*") : String("www.esp32.local");
    if (!dns.start(53, domain, IPAddress(192, 168, 4, 1))) return 0;
    host_udp_deliver(data + 1, size - 1);
    dns.stop();
  }
  host_udp_reset();
  return 0;
}
