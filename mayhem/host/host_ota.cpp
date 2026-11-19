// Host pieces for the ArduinoOTA target: the Update sink and the UDP queue.
#include "Network.h"
#include "Update.h"
#include <deque>

UpdateClass Update;
HostNetworkManager Network;
HostEspClass ESP;

bool UpdateClass::begin(size_t size, int command, int, uint8_t, const char *) {
  if (command != U_FLASH && command != U_FLASHFS && command != U_SPIFFS) { _error = "bad command"; return false; }
  if (size == 0 || (size != UPDATE_SIZE_UNKNOWN && size > (4u << 20))) { _error = "bad size"; return false; }
  _size = size; _written = 0; _active = true; _error = ""; _md5 = "";
  _hash.begin();
  return true;
}
size_t UpdateClass::write(uint8_t *data, size_t len) {
  if (!_active) return 0;
  if (_size != UPDATE_SIZE_UNKNOWN && len > _size - _written) len = _size - _written;
  _hash.add(data, len);
  _written += len;
  return len;
}
bool UpdateClass::end(bool evenIfRemaining) {
  if (!_active) return false;
  _active = false;
  if (!evenIfRemaining && _size != UPDATE_SIZE_UNKNOWN && _written != _size) { _error = "incomplete"; return false; }
  _hash.calculate();
  if (_md5.length() && !_md5.equalsIgnoreCase(_hash.toString())) { _error = "md5 mismatch"; return false; }
  return true;
}

static std::deque<std::string> g_udp_q;
static std::string g_udp_last;
void host_udp_queue(const uint8_t *data, size_t len) { g_udp_q.emplace_back((const char *)data, len); }
int NetworkUDP::parsePacket() {
  if (!_bound || g_udp_q.empty()) return 0;
  _rx = std::move(g_udp_q.front());
  g_udp_q.pop_front();
  _pos = 0;
  return (int)_rx.size();
}
int NetworkUDP::endPacket() { g_udp_last = _tx; return 1; }
const std::string &host_udp_last_reply() { return g_udp_last; }
void host_udp_queue_reset() { g_udp_q.clear(); g_udp_last.clear(); }
