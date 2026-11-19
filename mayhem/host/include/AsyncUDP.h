// Host stand-in for libraries/AsyncUDP/src/AsyncUDP.h (fuzz build only).
//
// No lwIP: listen() just records the handler, host_udp_deliver() hands a
// datagram (the fuzz input) to the handler of the most recent listener as an
// AsyncUDPPacket, and every reply (sendTo/writeTo/packet.send) is appended to
// a transcript the tests can inspect.
#pragma once
#include "host_arduino.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include <functional>
#include <string>

#ifndef CONFIG_TCP_MSS
#define CONFIG_TCP_MSS 1436
#endif
typedef enum { TCPIP_ADAPTER_IF_STA = 0, TCPIP_ADAPTER_IF_AP, TCPIP_ADAPTER_IF_ETH, TCPIP_ADAPTER_IF_PPP, TCPIP_ADAPTER_IF_MAX } tcpip_adapter_if_t;

class AsyncUDP;
class AsyncUDPPacket;
class AsyncUDPMessage;
typedef std::function<void(AsyncUDPPacket &packet)> AuPacketHandlerFunction;
typedef std::function<void(void *arg, AsyncUDPPacket &packet)> AuPacketHandlerFunctionWithArg;

class AsyncUDPMessage : public Print {
  std::string _buf;
  size_t _cap;

public:
  AsyncUDPMessage(size_t size = CONFIG_TCP_MSS) : _cap(size) {}
  virtual ~AsyncUDPMessage() {}
  size_t write(const uint8_t *data, size_t len) override {
    size_t n = std::min(len, space());
    _buf.append((const char *)data, n);
    return n;
  }
  size_t write(uint8_t data) override { return write(&data, 1); }
  size_t space() { return _cap - _buf.size(); }
  uint8_t *data() { return (uint8_t *)_buf.data(); }
  size_t length() { return _buf.size(); }
  void flush() override { _buf.clear(); }
  operator bool() { return _cap > 0; }
};

class AsyncUDPPacket : public Stream {
  AsyncUDP *_udp;
  const uint8_t *_data;
  size_t _len, _index = 0;
  IPAddress _remote, _local;
  uint16_t _rport, _lport;

public:
  AsyncUDPPacket(AsyncUDP *udp, const uint8_t *data, size_t len, IPAddress remote, uint16_t rport, IPAddress local, uint16_t lport)
    : _udp(udp), _data(data), _len(len), _remote(remote), _local(local), _rport(rport), _lport(lport) {}
  virtual ~AsyncUDPPacket() {}
  uint8_t *data() { return (uint8_t *)_data; }
  size_t length() { return _len; }
  bool isBroadcast() { return false; }
  bool isMulticast() { return false; }
  bool isIPv6() { return false; }
  tcpip_adapter_if_t interface() { return TCPIP_ADAPTER_IF_AP; }
  IPAddress localIP() { return _local; }
  IPAddress localIPv6() { return IPAddress(); }
  uint16_t localPort() { return _lport; }
  IPAddress remoteIP() { return _remote; }
  IPAddress remoteIPv6() { return IPAddress(); }
  uint16_t remotePort() { return _rport; }
  void remoteMac(uint8_t *mac) { memset(mac, 0, 6); }
  size_t send(AsyncUDPMessage &message);
  int available() override { return (int)(_len - _index); }
  size_t read(uint8_t *data, size_t len) {
    size_t n = std::min(len, _len - _index);
    memcpy(data, _data + _index, n);
    _index += n;
    return n;
  }
  int read() override { return _index < _len ? _data[_index++] : -1; }
  int peek() override { return _index < _len ? _data[_index] : -1; }
  void flush() override { _index = _len; }
  size_t write(const uint8_t *data, size_t len) override;
  size_t write(uint8_t data) override { return write(&data, 1); }
};

class AsyncUDP : public Print {
  AuPacketHandlerFunction _handler;
  uint16_t _port = 0;
  bool _connected = false;

public:
  AsyncUDP() {}
  virtual ~AsyncUDP();
  void onPacket(AuPacketHandlerFunctionWithArg cb, void *arg = NULL) {
    onPacket([cb, arg](AsyncUDPPacket &p) { cb(arg, p); });
  }
  void onPacket(AuPacketHandlerFunction cb) { _handler = cb; }
  bool listen(const ip_addr_t *, uint16_t port) { return listen(port); }
  bool listen(const IPAddress, uint16_t port) { return listen(port); }
  bool listen(uint16_t port);
  bool connect(const IPAddress, uint16_t port) { _connected = true; _port = port; return true; }
  void close();
  size_t writeTo(const uint8_t *data, size_t len, const IPAddress addr, uint16_t port, tcpip_adapter_if_t tcpip_if = TCPIP_ADAPTER_IF_MAX);
  size_t sendTo(AsyncUDPMessage &message, const IPAddress addr, uint16_t port, tcpip_adapter_if_t tcpip_if = TCPIP_ADAPTER_IF_MAX) {
    return writeTo(message.data(), message.length(), addr, port, tcpip_if);
  }
  size_t write(const uint8_t *data, size_t len) override { return writeTo(data, len, IPAddress(), _port); }
  size_t write(uint8_t data) override { return write(&data, 1); }
  bool connected() { return _connected; }
  operator bool() { return _connected; }
  void deliver(const uint8_t *data, size_t len, IPAddress remote, uint16_t rport);
};

// Deliver one datagram to the most recently listening AsyncUDP. False if none listens.
bool host_udp_deliver(const uint8_t *data, size_t len);
// All datagrams sent since the last reset, each prefixed by a 2-byte big-endian length.
const std::string &host_udp_tx();
void host_udp_reset();
