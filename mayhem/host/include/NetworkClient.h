// Host stand-in for libraries/Network/src/NetworkClient.h (fuzz build only).
//
// Instead of an lwIP socket, a NetworkClient is a handle on a HostConn: an
// in-memory byte stream holding what the peer sent (the fuzz input) and a
// string collecting what the library wrote back. The peer is treated as having
// sent everything up front and then half-closed: connected() stays true while
// unread bytes remain, so the library sees exactly the input and then EOF.
#pragma once
#include "host_arduino.h"
#include <memory>
#include <string>

struct HostConn {
  std::string rx;
  size_t pos = 0;
  std::string tx;
  bool open = true;
};

// Queue a connection; NetworkServer::accept() / NetworkClient::connect() hand them out in order.
void host_net_set_incoming(const uint8_t *data, size_t len);
std::shared_ptr<HostConn> host_net_take_incoming();
// Everything written on the last accepted / connected connection.
const std::string &host_net_last_tx();
void host_net_reset();

class ESPLwIPClient : public Client {
public:
  virtual void setConnectionTimeout(uint32_t milliseconds) = 0;
  using Client::connect;
  virtual int connect(IPAddress ip, uint16_t port, int32_t timeout) = 0;
  virtual int connect(const char *host, uint16_t port, int32_t timeout) = 0;
};

class NetworkClient : public ESPLwIPClient {
protected:
  std::shared_ptr<HostConn> _conn;
  bool _sse = false;

public:
  NetworkClient *next = nullptr;
  NetworkClient() {}
  explicit NetworkClient(std::shared_ptr<HostConn> c) : _conn(std::move(c)) {}
  ~NetworkClient() {}
  int connect(IPAddress ip, uint16_t port) override;
  int connect(IPAddress ip, uint16_t port, int32_t timeout_ms) override;
  int connect(const char *host, uint16_t port) override;
  int connect(const char *host, uint16_t port, int32_t timeout_ms) override;
  size_t write(uint8_t data) override;
  size_t write(const uint8_t *buf, size_t size) override;
  size_t write_P(PGM_P buf, size_t size) { return write((const uint8_t *)buf, size); }
  size_t write(Stream &stream);
  size_t write(Stream &stream, size_t length);
  void flush() override {}
  int available() override;
  int read() override;
  int read(uint8_t *buf, size_t size) override;
  size_t readBytes(char *buffer, size_t length) override;
  size_t readBytes(uint8_t *buffer, size_t length) { return readBytes((char *)buffer, length); }
  int peek() override;
  void clear();
  void stop() override;
  uint8_t connected() override;
  void setSSE(bool sse) { _sse = sse; }
  bool isSSE() { return _sse; }
  operator bool() override { return connected(); }
  bool operator==(const bool value) { return bool() == value; }
  bool operator!=(const bool value) { return bool() != value; }
  bool operator==(const NetworkClient &rhs) { return _conn == rhs._conn; }
  bool operator!=(const NetworkClient &rhs) { return !this->operator==(rhs); }
  virtual int fd() const { return _conn ? 3 : -1; }
  void setConnectionTimeout(uint32_t) override {}
  int setNoDelay(bool) { return 0; }
  bool getNoDelay() { return true; }
  IPAddress remoteIP() const { return IPAddress(192, 168, 4, 2); }
  uint16_t remotePort() const { return 49152; }
  IPAddress localIP() const { return IPAddress(192, 168, 4, 1); }
  uint16_t localPort() const { return 80; }
  using Print::write;
};
