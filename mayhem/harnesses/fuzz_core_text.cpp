// Fuzz target: cores/esp32 text parsers that sketches run on received strings
// (HTTP args, serial/console lines, MQTT/JSON payload fields, config files):
// IPAddress::fromString (IPv4, IPv6 + zone), MacAddress::fromString (6/8-byte),
// base64::decode, HEXBuilder::hex2bytes / isHexString, BTAddress(String), and
// the Stream parsing API (parseInt/parseFloat/find/findUntil/readStringUntil/
// readBytesUntil) over a StreamString, plus String's numeric conversions and
// search/replace. Byte 0 selects the parser, the rest is the text.
#include <Arduino.h>
#include <StreamString.h>
#include <MacAddress.h>
#include <HEXBuilder.h>
#include <BTAddress.h>
#include <base64.h>

static size_t use(const String &s) { return s.length(); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  host_reset_clock();
  const uint8_t sel = data[0];
  String text;
  text.concat((const char *)data + 1, size - 1);  // NUL-terminated copy (may hold embedded NULs)
  const char *c = text.c_str();
  volatile size_t sink = 0;
  switch (sel % 8) {
    case 0: {
      IPAddress ip;
      if (ip.fromString(c)) {
        String s = ip.toString(true);
        IPAddress again;
        sink += again.fromString(s) + (again == ip) + use(ip.toString());
        StreamString ss;
        ss.print(ip);
        sink += ss.length();
      }
      break;
    }
    case 1: {
      MacAddress mac;
      if (mac.fromString(c)) {
        String s = mac.toString();
        sink += use(s) + (uint64_t)mac;
      }
      break;
    }
    case 2: {
      String out = base64::decode(c, strlen(c));
      sink += use(out) + use(base64::encode(out));
      break;
    }
    case 3: {
      unsigned char buf[64];
      sink += HEXBuilder::hex2bytes(buf, sel & 0x80 ? sizeof(buf) : 7, c);
      sink += HEXBuilder::isHexString(c, strlen(c));
      sink += use(HEXBuilder::bytes2hex(buf, 16));
      break;
    }
    case 4: {
      BTAddress a(text);
      sink += use(a.toString());
      break;
    }
    case 5: {
      // Stream parsing API, driven by the text itself.
      StreamString ss;
      ss.write((const uint8_t *)data + 1, size - 1);
      ss.setTimeout(0);
      const char ign = (sel & 0x80) ? ',' : '\x01';  // Stream.h's NO_IGNORE_CHAR (#undef'd at its end)
      while (ss.available()) {
        int op = ss.read();
        if (op < 0) break;
        switch (op & 7) {
          case 0: sink += ss.parseInt(SKIP_ALL, ign); break;
          case 1: sink += ss.parseFloat(SKIP_WHITESPACE, ign) > 0; break;
          case 2: sink += ss.find("\r\n"); break;
          case 3: sink += ss.findUntil("key", "\n"); break;
          case 4: sink += use(ss.readStringUntil(';')); break;
          case 5: { char b[8]; sink += ss.readBytesUntil(':', b, sizeof(b)); break; }
          case 6: sink += use(ss.readString()); break;
          default: sink += ss.parseInt(SKIP_NONE); break;
        }
      }
      break;
    }
    default: {
      // String conversions / search / mutate.
      String s = text;
      // Accumulate unsigned: toInt() is atol() and may return LONG_MAX/LONG_MIN.
      sink += (size_t)s.toInt();
      sink += (size_t)(s.toFloat() > 1.0f) + (size_t)(s.toDouble() < -1.0);
      sink += (size_t)s.indexOf("=") + (size_t)s.lastIndexOf('/');
      sink += (size_t)s.startsWith("GET") + (size_t)s.endsWith("\r\n");
      s.replace("%20", " ");
      s.replace("a", "bcd");
      s.trim();
      s.toLowerCase();
      s.remove(0, s.length() / 3);
      sink += use(s.substring(1, s.length() / 2));
      String t = s + text;
      sink += (size_t)t.equalsIgnoreCase(text) + (size_t)t.compareTo(s);
      break;
    }
  }
  (void)sink;
  return 0;
}
