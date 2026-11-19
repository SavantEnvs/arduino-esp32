// Host stand-in for libraries/Network/src/NetworkUdp.h: begin() binds, and
// parsePacket() returns the next datagram queued with host_udp_queue().
#pragma once
#include "host_arduino.h"
#include <string>
#include <deque>
void host_udp_queue(const uint8_t *data, size_t len);
class NetworkUDP : public UDP {
  bool _bound = false;
  std::string _rx;
  size_t _pos = 0;
  std::string _tx;
public:
  NetworkUDP() {}
  ~NetworkUDP() {}
  uint8_t begin(IPAddress, uint16_t p) { return begin(p); }
  uint8_t begin(uint16_t) override { _bound = true; return 1; }
  uint8_t beginMulticast(IPAddress, uint16_t p) override { return begin(p); }
  void stop() override { _bound = false; }
  int beginMulticastPacket() { return 1; }
  int beginPacket() { _tx.clear(); return 1; }
  int beginPacket(IPAddress, uint16_t) override { _tx.clear(); return 1; }
  int beginPacket(const char *, uint16_t) override { _tx.clear(); return 1; }
  int endPacket() override;
  size_t write(uint8_t b) override { _tx.push_back((char)b); return 1; }
  size_t write(const uint8_t *buffer, size_t size) override { _tx.append((const char *)buffer, size); return size; }
  void flush() override {}
  int parsePacket() override;
  int available() override { return (int)(_rx.size() - _pos); }
  int read() override { return _pos < _rx.size() ? (uint8_t)_rx[_pos++] : -1; }
  int read(unsigned char *buffer, size_t len) override {
    size_t n = std::min(len, _rx.size() - _pos);
    memcpy(buffer, _rx.data() + _pos, n);
    _pos += n;
    return (int)n;
  }
  int read(char *buffer, size_t len) override { return read((unsigned char *)buffer, len); }
  int peek() override { return _pos < _rx.size() ? (uint8_t)_rx[_pos] : -1; }
  void clear() { _rx.clear(); _pos = 0; }
  IPAddress remoteIP() override { return IPAddress(192, 168, 4, 2); }
  uint16_t remotePort() override { return 40000; }
  using Print::write;
};
