// Host runtime for the arduino-esp32 fuzz build: the few board services the
// fuzzed parsers call (clock, RNG, MD5 ROM routine, sockets), implemented in
// memory so each input is processed deterministically and independently.
#include "host_arduino.h"
#include "NetworkClient.h"
#include "NetworkServer.h"
#include "esp_rom_md5.h"
#include "esp_netif_ip_addr.h"
#include "http_parser.h"

HostNullSerial Serial;

// ---- virtual clock -------------------------------------------------------
static unsigned long g_ms;
extern "C" void host_reset_clock(void) { g_ms = 1000; }
extern "C" unsigned long millis(void) { return ++g_ms; }
extern "C" unsigned long micros(void) { return (++g_ms) * 1000UL; }
extern "C" void delay(uint32_t ms) { g_ms += ms ? ms : 1; }
extern "C" void delayMicroseconds(uint32_t us) { g_ms += us / 1000 + 1; }
extern "C" void yield(void) { ++g_ms; }

// ---- deterministic RNG (WebServer nonces, random()) ------------------------
static uint32_t g_rng = 0x12345678u;
extern "C" uint32_t esp_random(void) {
  g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
  return g_rng;
}
long random(long howbig) { return howbig <= 0 ? 0 : (long)(esp_random() % (uint32_t)howbig); }
long random(long howsmall, long howbig) { return howsmall >= howbig ? howsmall : howsmall + random(howbig - howsmall); }
void randomSeed(unsigned long s) { g_rng = s ? (uint32_t)s : 1; }

extern "C" const char *esp_err_to_name(esp_err_t) { return "ESP_ERR"; }
extern "C" esp_ip6_addr_type_t esp_netif_ip6_get_addr_type(esp_ip6_addr_t *a) {
  uint8_t b0 = (uint8_t)(a->addr[0] & 0xff), b1 = (uint8_t)((a->addr[0] >> 8) & 0xff);
  if (b0 == 0xfe && (b1 & 0xc0) == 0x80) return ESP_IP6_ADDR_IS_LINK_LOCAL;
  if ((b0 & 0xfe) == 0xfc) return ESP_IP6_ADDR_IS_UNIQUE_LOCAL;
  if ((b0 & 0xe0) == 0x20) return ESP_IP6_ADDR_IS_GLOBAL;
  return ESP_IP6_ADDR_IS_UNKNOWN;
}

extern "C" const char *http_method_str(enum http_method m) {
  static const char *names[] = {
#define XX(num, name, string) #string,
    HTTP_METHOD_MAP(XX)
#undef XX
  };
  return (unsigned)m < sizeof(names) / sizeof(names[0]) ? names[m] : "<unknown>";
}

// ---- MD5 (RFC 1321), standing in for the ESP32 ROM routine ---------------
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))
#define MD5STEP(f, w, x, y, z, in, s) (w += f(x, y, z) + in, w = (w << s | w >> (32 - s)) + x)
static void md5_transform(uint32_t buf[4], const uint8_t blk[64]) {
  uint32_t in[16];
  for (int i = 0; i < 16; i++) in[i] = (uint32_t)blk[4 * i] | (uint32_t)blk[4 * i + 1] << 8 | (uint32_t)blk[4 * i + 2] << 16 | (uint32_t)blk[4 * i + 3] << 24;
  uint32_t a = buf[0], b = buf[1], c = buf[2], d = buf[3];
  MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);  MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17); MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);  MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17); MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);  MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17); MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7); MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17); MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);
  MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);  MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14); MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14); MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14); MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5); MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14); MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);
  MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);  MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16); MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);  MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16); MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4); MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16); MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16); MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);
  MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);  MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15); MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6); MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15); MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15); MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15); MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);
  buf[0] += a; buf[1] += b; buf[2] += c; buf[3] += d;
}
extern "C" void esp_rom_md5_init(md5_context_t *c) {
  c->state[0] = 0x67452301; c->state[1] = 0xefcdab89; c->state[2] = 0x98badcfe; c->state[3] = 0x10325476;
  c->count[0] = c->count[1] = 0;
}
extern "C" void esp_rom_md5_update(md5_context_t *c, const void *data, uint32_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint32_t have = (c->count[0] >> 3) & 63;
  uint32_t lo = c->count[0];
  c->count[0] += len << 3;
  if (c->count[0] < lo) c->count[1]++;
  c->count[1] += len >> 29;
  while (len--) {
    c->buffer[have++] = *p++;
    if (have == 64) { md5_transform(c->state, c->buffer); have = 0; }
  }
}
extern "C" void esp_rom_md5_final(uint8_t *digest, md5_context_t *c) {
  uint8_t bits[8];
  for (int i = 0; i < 4; i++) { bits[i] = (uint8_t)(c->count[0] >> (8 * i)); bits[4 + i] = (uint8_t)(c->count[1] >> (8 * i)); }
  static const uint8_t pad0 = 0x80, zero = 0;
  esp_rom_md5_update(c, &pad0, 1);
  while (((c->count[0] >> 3) & 63) != 56) esp_rom_md5_update(c, &zero, 1);
  esp_rom_md5_update(c, bits, 8);
  for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) digest[4 * i + j] = (uint8_t)(c->state[i] >> (8 * j));
}

// ---- in-memory sockets ----------------------------------------------------
#include <deque>
static std::deque<std::shared_ptr<HostConn>> g_incoming;
static std::shared_ptr<HostConn> g_last;
static const std::string g_empty;
void host_net_set_incoming(const uint8_t *data, size_t len) {
  auto c = std::make_shared<HostConn>();
  c->rx.assign((const char *)data, len);
  g_incoming.push_back(std::move(c));
}
std::shared_ptr<HostConn> host_net_take_incoming() {
  if (g_incoming.empty()) return nullptr;
  std::shared_ptr<HostConn> c = std::move(g_incoming.front());
  g_incoming.pop_front();
  g_last = c;
  return c;
}
const std::string &host_net_last_tx() { return g_last ? g_last->tx : g_empty; }
void host_net_reset() { g_incoming.clear(); g_last.reset(); }

NetworkClient NetworkServer::accept() {
  if (!_listening) return NetworkClient();
  return NetworkClient(host_net_take_incoming());
}
bool NetworkServer::hasClient() { return _listening && !g_incoming.empty(); }

int NetworkClient::connect(IPAddress, uint16_t) { _conn = host_net_take_incoming(); return _conn ? 1 : 0; }
int NetworkClient::connect(IPAddress ip, uint16_t port, int32_t) { return connect(ip, port); }
int NetworkClient::connect(const char *, uint16_t) { _conn = host_net_take_incoming(); return _conn ? 1 : 0; }
int NetworkClient::connect(const char *host, uint16_t port, int32_t) { return connect(host, port); }
size_t NetworkClient::write(uint8_t data) { return write(&data, 1); }
size_t NetworkClient::write(const uint8_t *buf, size_t size) {
  if (!_conn || !_conn->open) return 0;
  // Keep the response transcript bounded; the bytes are only inspected by tests.
  if (_conn->tx.size() < (1u << 20)) _conn->tx.append((const char *)buf, std::min(size, (size_t)(1u << 20) - _conn->tx.size()));
  return size;
}
size_t NetworkClient::write(Stream &stream) {
  uint8_t b[256]; size_t n = 0; int r;
  while ((r = (int)stream.readBytes(b, sizeof(b))) > 0) n += write(b, (size_t)r);
  return n;
}
size_t NetworkClient::write(Stream &stream, size_t length) {
  uint8_t b[256]; size_t n = 0;
  while (n < length) {
    size_t r = stream.readBytes(b, std::min(sizeof(b), length - n));
    if (!r) break;
    n += write(b, r);
  }
  return n;
}
int NetworkClient::available() {
  if (!_conn || !_conn->open) return 0;
  return (int)(_conn->rx.size() - _conn->pos);
}
int NetworkClient::read() {
  if (!available()) return -1;
  return (uint8_t)_conn->rx[_conn->pos++];
}
int NetworkClient::read(uint8_t *buf, size_t size) {
  int a = available();
  if (a <= 0) return -1;
  size_t n = std::min(size, (size_t)a);
  memcpy(buf, _conn->rx.data() + _conn->pos, n);
  _conn->pos += n;
  return (int)n;
}
size_t NetworkClient::readBytes(char *buffer, size_t length) {
  int r = read((uint8_t *)buffer, length);
  return r < 0 ? 0 : (size_t)r;
}
int NetworkClient::peek() {
  if (!available()) return -1;
  return (uint8_t)_conn->rx[_conn->pos];
}
void NetworkClient::clear() { if (_conn) _conn->pos = _conn->rx.size(); }
void NetworkClient::stop() {
  if (_conn) _conn->open = false;
  _conn.reset();
}
uint8_t NetworkClient::connected() { return available() > 0; }

// ---- newlib's itoa/utoa (WString uses them; glibc has none) ---------------
static char *host_utoa_impl(unsigned long v, char *s, int radix) {
  char tmp[sizeof(unsigned long) * 8 + 1];
  int i = 0;
  if (radix < 2 || radix > 36) { s[0] = 0; return s; }
  do { int d = (int)(v % (unsigned)radix); tmp[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v /= (unsigned)radix; } while (v);
  int j = 0;
  while (i) s[j++] = tmp[--i];
  s[j] = 0;
  return s;
}
extern "C" char *utoa(unsigned int v, char *s, int radix) { return host_utoa_impl(v, s, radix); }
extern "C" char *itoa(int v, char *s, int radix) {
  if (v < 0 && radix == 10) { s[0] = '-'; host_utoa_impl(0UL - (unsigned long)(long)v, s + 1, radix); return s; }
  return host_utoa_impl((unsigned int)v, s, radix);
}

// ---- in-memory UDP ---------------------------------------------------------
#include "AsyncUDP.h"
static AsyncUDP *g_listener;
static std::string g_udp_tx;
const std::string &host_udp_tx() { return g_udp_tx; }
void host_udp_reset() { g_udp_tx.clear(); }
bool AsyncUDP::listen(uint16_t port) { _port = port; _connected = true; g_listener = this; return true; }
void AsyncUDP::close() { _connected = false; if (g_listener == this) g_listener = nullptr; }
AsyncUDP::~AsyncUDP() { close(); }
size_t AsyncUDP::writeTo(const uint8_t *data, size_t len, const IPAddress, uint16_t, tcpip_adapter_if_t) {
  if (g_udp_tx.size() < (1u << 20)) {
    g_udp_tx.push_back((char)(len >> 8));
    g_udp_tx.push_back((char)len);
    g_udp_tx.append((const char *)data, len);
  }
  return len;
}
void AsyncUDP::deliver(const uint8_t *data, size_t len, IPAddress remote, uint16_t rport) {
  if (!_handler) return;
  AsyncUDPPacket p(this, data, len, remote, rport, IPAddress(192, 168, 4, 1), _port);
  _handler(p);
}
size_t AsyncUDPPacket::send(AsyncUDPMessage &m) { return _udp->writeTo(m.data(), m.length(), _remote, _rport); }
size_t AsyncUDPPacket::write(const uint8_t *data, size_t len) { return _udp->writeTo(data, len, _remote, _rport); }
bool host_udp_deliver(const uint8_t *data, size_t len) {
  if (!g_listener || !g_listener->connected()) return false;
  g_listener->deliver(data, len, IPAddress(192, 168, 4, 2), 5353);
  return true;
}
