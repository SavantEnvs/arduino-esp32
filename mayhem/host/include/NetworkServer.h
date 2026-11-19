// Host stand-in for libraries/Network/src/NetworkServer.h: accept() hands out the
// connection queued with host_net_set_incoming(), once.
#pragma once
#include "host_arduino.h"
#include "NetworkClient.h"

class NetworkServer {
public:
  NetworkServer(uint16_t port = 80, uint8_t max_clients = 4) : _port(port) {}
  NetworkServer(const IPAddress &addr, uint16_t port = 80, uint8_t max_clients = 4) : _port(port) {}
  NetworkClient accept();
  NetworkClient available() { return accept(); }
  void begin(uint16_t port = 0) { _listening = true; }
  void begin(uint16_t port, int) { _listening = true; }
  void setNoDelay(bool) {}
  bool getNoDelay() { return true; }
  bool hasClient();
  void end() { _listening = false; }
  void close() { _listening = false; }
  void stop() { _listening = false; }
  operator bool() { return _listening; }

private:
  uint16_t _port;
  bool _listening = false;
};
