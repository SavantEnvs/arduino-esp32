// Known-answer functional tests for the arduino-esp32 code the fuzz targets
// drive, built with normal flags by mayhem/build.sh and run by mayhem/test.sh.
// Each CHECK compares what the upstream code produced against a fixed
// expected value (parsed fields, encoded bytes, HTTP/DNS responses), so a
// no-op or neutered build fails. Prints "PASS <name>" / "FAIL <name>" lines.
#include <Arduino.h>
#include <StreamString.h>
#include <HEXBuilder.h>
#include <MD5Builder.h>
#include <SHA1Builder.h>
#include <base64.h>
#include <WebServer.h>
#include <uri/UriBraces.h>
#include <HTTPClient.h>
#include <DNSServer.h>
#include <NetBIOS.h>
#include "NetworkClient.h"
#include "AsyncUDP.h"
#include "USBHIDReportMapParse.h"
#include "USBHostHIDKeyboardDecode.h"
#include "scan/BLEAdvertisedDeviceImpl.h"
#include "advertising/BLEBeacon.h"
#include "advertising/BLEEddystone.h"
#include "ZigbeeOTAFileParser.h"
#include <Wire.h>
#include <ArduinoOTA.h>
void host_udp_queue_reset();
const std::string &host_udp_last_reply();
void host_i2c_feed(const uint8_t *data, size_t len);
#include <string>

struct BLEScanImplCommon {
  static BLEAdvertisedDevice makeAdvertisedDeviceHandle(std::shared_ptr<BLEAdvertisedDevice::Impl> impl) {
    return BLEAdvertisedDevice(std::move(impl));
  }
};

static int g_pass, g_fail;
static void check(const char *name, bool ok, const std::string &got = "") {
  if (ok) { g_pass++; printf("PASS %s\n", name); }
  else { g_fail++; printf("FAIL %s%s%s\n", name, got.empty() ? "" : " got: ", got.c_str()); }
}
static void checkEq(const char *name, const String &got, const char *want) {
  check(name, got == want, std::string(got.c_str()));
}
static bool contains(const std::string &h, const std::string &n) { return h.find(n) != std::string::npos; }

static std::string http_exchange(const std::string &req) {
  host_reset_clock();
  host_net_reset();
  WebServer s(80);
  s.on("/", [&]() {
    String r;
    for (int i = 0; i < s.args(); i++) r += s.argName(i) + "=" + s.arg(i) + ";";
    s.send(200, "text/plain", r);
  });
  s.on(UriBraces("/users/{}/posts/{}"), [&]() { s.send(200, "text/plain", s.pathArg(0) + "/" + s.pathArg(1)); });
  s.on("/basic", [&]() {
    if (!s.authenticate("admin", "secret")) return s.requestAuthentication(BASIC_AUTH);
    s.send(200, "text/plain", "authorized");
  });
  s.onNotFound([&]() { s.send(404, "text/plain", "nope:" + s.uri()); });
  s.begin();
  host_net_set_incoming((const uint8_t *)req.data(), req.size());
  for (int i = 0; i < 4; i++) s.handleClient();
  std::string tx = host_net_last_tx();
  s.close();
  return tx;
}

static int http_get(const std::string &url, const std::string &resp, String &body) {
  host_reset_clock();
  host_net_reset();
  size_t start = 0, sep;
  while ((sep = resp.find("\n--NEXT--\n", start)) != std::string::npos) {
    host_net_set_incoming((const uint8_t *)resp.data() + start, sep - start);
    start = sep + 10;
  }
  host_net_set_incoming((const uint8_t *)resp.data() + start, resp.size() - start);
  NetworkClient client;
  HTTPClient http;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setTimeout(100);
  if (!http.begin(client, String(url.c_str()))) return -1000;
  int code = http.GET();
  if (code > 0) body = http.getString();
  http.end();
  return code;
}

static std::string dns_query(const char *name, const String &domain) {
  host_udp_reset();
  DNSServer dns;
  dns.start(53, domain, IPAddress(192, 168, 4, 1));
  std::string q("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12);
  const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t n = dot ? (size_t)(dot - p) : strlen(p);
    q.push_back((char)n);
    q.append(p, n);
    p += n + (dot ? 1 : 0);
  }
  q.append("\x00\x00\x01\x00\x01", 5);
  host_udp_deliver((const uint8_t *)q.data(), q.size());
  dns.stop();
  return host_udp_tx();
}

int main() {
  // ---- core text parsers ----
  { IPAddress ip; check("ipv4_parse", ip.fromString("192.168.1.10")); checkEq("ipv4_tostring", ip.toString(), "192.168.1.10");
    check("ipv4_octet", ip[3] == 10); }
  { IPAddress ip; check("ipv4_reject_300", !ip.fromString("300.1.1.1")); }
  { IPAddress ip; check("ipv6_parse", ip.fromString("2001:db8::1")); check("ipv6_type", ip.type() == IPv6);
    checkEq("ipv6_tostring", ip.toString(), "2001:db8::1"); }
  checkEq("base64_decode", base64::decode("aGVsbG8gd29ybGQ="), "hello world");
  checkEq("base64_encode", base64::encode(String("hello world")), "aGVsbG8gd29ybGQ=");
  { unsigned char b[4] = {0}; size_t n = HEXBuilder::hex2bytes(b, 4, "deadBEEF");
    check("hex2bytes", n == 4 && b[0] == 0xde && b[1] == 0xad && b[2] == 0xbe && b[3] == 0xef); }
  { MD5Builder m; m.begin(); m.add("abc"); m.calculate(); checkEq("md5_abc", m.toString(), "900150983cd24fb0d6963f7d28e17f72"); }
  { SHA1Builder h; h.begin(); h.add("abc"); h.calculate(); checkEq("sha1_abc", h.toString(), "a9993e364706816aba3e25717850c26c9cd0d89d"); }
  { StreamString ss; ss.print("  -42,17 x3.5"); ss.setTimeout(0);
    long a = ss.parseInt(); long b = ss.parseInt(); float c = ss.parseFloat();
    check("stream_parse", a == -42 && b == 17 && c > 3.49f && c < 3.51f); }
  { String s("key=val;rest"); check("string_ops", s.indexOf('=') == 3 && s.substring(4, 7) == "val" && String("1234").toInt() == 1234); }

  // ---- WebServer ----
  { std::string r = http_exchange("GET /users/7/posts/9 HTTP/1.1\r\nHost: esp\r\n\r\n");
    check("web_pathargs_status", contains(r, "HTTP/1.1 200 OK"), r.substr(0, 40)); check("web_pathargs_body", contains(r, "\r\n\r\n7/9")); }
  { std::string r = http_exchange("GET /?a=1&b=%41x+y HTTP/1.1\r\nHost: esp\r\n\r\n");
    check("web_query_args", contains(r, "a=1;b=Ax y;"), r); }
  { std::string r = http_exchange("POST / HTTP/1.1\r\nHost: esp\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nx=1&y=hello");
    check("web_post_form", contains(r, "x=1;y=hello;"), r); }
  { std::string r = http_exchange("GET /basic HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n");
    check("web_basic_ok", contains(r, "200 OK") && contains(r, "authorized"), r.substr(0, 40)); }
  { std::string r = http_exchange("GET /basic HTTP/1.1\r\nAuthorization: Basic YWRtaW46d3Jvbmc=\r\n\r\n");
    check("web_basic_denied", contains(r, "401") && contains(r, "WWW-Authenticate: Basic"), r.substr(0, 40)); }
  { std::string r = http_exchange("GET /missing HTTP/1.1\r\n\r\n");
    check("web_not_found", contains(r, "404") && contains(r, "nope:/missing"), r.substr(0, 40)); }

  // ---- HTTPClient ----
  { String body; int code = http_get("http://example.com/x", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", body);
    check("http_get_code", code == 200, std::to_string(code)); checkEq("http_get_body", body, "hello"); }
  { String body; int code = http_get("http://example.com/x", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n", body);
    check("http_chunked_code", code == 200, std::to_string(code)); checkEq("http_chunked_body", body, "hello"); }
  { String body; int code = http_get("http://example.com/a",
      "HTTP/1.1 302 Found\r\nLocation: http://other.org/b\r\nContent-Length: 0\r\n\r\n\n--NEXT--\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", body);
    check("http_redirect_code", code == 200, std::to_string(code)); checkEq("http_redirect_body", body, "ok"); }
  { String body; check("http_404", http_get("http://example.com/x", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", body) == 404); }

  // ---- DNSServer ----
  { std::string r = dns_query("www.esp32.local", "esp32.local");
    check("dns_answer_ip", r.size() > 2 && contains(r, std::string("\xc0\xa8\x04\x01", 4)) && (uint8_t)r[2] == 0x12 && (uint8_t)r[3] == 0x34); }
  { std::string r = dns_query("other.org", "esp32.local");
    check("dns_other_domain_no_ip", r.size() > 2 && !contains(r, std::string("\xc0\xa8\x04\x01", 4))); }

  // ---- NetBIOS ----
  { host_udp_reset();
    NetBIOS nb; nb.begin("ESP32");
    std::string q("\xab\xcd\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20", 13);
    const char *name = "ESP32";
    for (int i = 0; i < 16; i++) { uint8_t c = i < 5 ? name[i] : ' '; q.push_back((char)('A' + (c >> 4))); q.push_back((char)('A' + (c & 15))); }
    q.append("\x00\x00\x20\x00\x01", 5);
    host_udp_deliver((const uint8_t *)q.data(), q.size());
    std::string r = host_udp_tx(); nb.end();
    check("netbios_answer", r.size() > 6 && (uint8_t)r[2] == 0xab && (uint8_t)r[3] == 0xcd && (uint8_t)r[4] == 0x85, std::to_string(r.size())); }

  // ---- USB HID ----
  { static const uint8_t kbd[] = {0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01,
                                  0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x06, 0x75, 0x08,
                                  0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xc0};
    usbhid_report_map_t *m = usbhid_parse_report_map(kbd, sizeof(kbd));
    check("hid_keyboard_map", m && m->usage == USBHID_USAGE_KEYBOARD && m->reports_len >= 1 && m->reports[0].value_len == 8,
          m ? std::to_string(m->usage) + "/" + std::to_string(m->reports_len) + "/" + std::to_string(m->reports_len ? m->reports[0].value_len : 0) : "null");
    if (m) usbhid_free_report_map(m); }
  { uint8_t keys[6] = {0x04, 0x05, 0, 0, 0, 0}; char buf[8];
    size_t n = usbHostHidBootReportAppendAscii(buf, sizeof(buf), 0, keys, 0, KeyboardLayout_en_US);
    check("hid_boot_ascii", n == 2 && buf[0] == 'a' && buf[1] == 'b', std::string(buf, n));
    check("hid_boot_shift", usbHostHidBootReportUsageToAscii(0x02, 0x04, 0, KeyboardLayout_en_US) == 'A'); }

  // ---- BLE ----
  { static const uint8_t adv[] = {0x02, 0x01, 0x06, 0x04, 0x09, 'E', 'S', 'P',
                                  0x1a, 0xff, 0x4c, 0x00, 0x02, 0x15, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x00, 0x07, 0x00, 0x09, 0xc5};
    auto impl = std::make_shared<BLEAdvertisedDevice::Impl>();
    impl->parsePayload(adv, sizeof(adv));
    BLEAdvertisedDevice d = BLEScanImplCommon::makeAdvertisedDeviceHandle(impl);
    checkEq("ble_name", d.getName(), "ESP");
    check("ble_frame_ibeacon", d.getFrameType() == BLEAdvertisedDevice::IBeacon);
    BLEBeacon b; check("ble_ibeacon_fields", d.getBeacon(b) && b.getMajor() == 7 && b.getMinor() == 9 && b.getSignalPower() == (int8_t)0xc5,
                       std::to_string(b.getMajor()) + "/" + std::to_string(b.getMinor())); }
  { static const uint8_t adv[] = {0x03, 0x03, 0xaa, 0xfe, 0x0a, 0x16, 0xaa, 0xfe, 0x10, 0xf4, 0x01, 'e', 's', 'p', 0x07};
    auto impl = std::make_shared<BLEAdvertisedDevice::Impl>();
    impl->parsePayload(adv, sizeof(adv));
    BLEAdvertisedDevice d = BLEScanImplCommon::makeAdvertisedDeviceHandle(impl);
    BLEEddystoneURL u;
    check("ble_frame_eddystone_url", d.getFrameType() == BLEAdvertisedDevice::EddystoneURL);
    check("ble_eddystone_url", d.getEddystoneURL(u) && u.getURL() == "https://www.esp.com", std::string(u.getURL().c_str())); }

  // ---- Zigbee OTA file ----
  { std::vector<uint8_t> f(56, 0);
    uint32_t magic = 0x0BEEF11E; memcpy(&f[0], &magic, 4);
    f[6] = 56;  // hdr_length
    const uint8_t elem[] = {0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 'D', 'A', 'T', 'A'};
    f.insert(f.end(), elem, elem + sizeof(elem));
    uint32_t total = (uint32_t)f.size(); memcpy(&f[52], &total, 4);
    zb_ota_file_parser_t p; zb_ota_file_parser_init(&p, total);
    std::string got;
    for (size_t off = 0; off < f.size(); off += 16) {
      size_t n = std::min((size_t)16, f.size() - off);
      zb_ota_file_parser_setup(&p, (uint16_t)n, &f[off]);
      esp_err_t r;
      do { r = zb_ota_file_parser_process(&p);
           if (zb_ota_file_parser_is_element_value(&p)) got.append((const char *)p.element.val, p.element.length);
      } while (r == ESP_ERR_NOT_FINISHED);
    }
    check("zigbee_ota_element", got == "DATA", got);
    check("zigbee_ota_check", zb_ota_file_parser_check(&p) == ESP_OK);
    zb_ota_file_parser_t q; zb_ota_file_parser_init(&q, total + 1);
    zb_ota_file_parser_setup(&q, (uint16_t)f.size(), f.data());
    while (zb_ota_file_parser_process(&q) == ESP_ERR_NOT_FINISHED) {}
    check("zigbee_ota_truncated_rejected", zb_ota_file_parser_check(&q) != ESP_OK); }

  // ---- Wire ----
  { static uint8_t dev[300]; for (int i = 0; i < 300; i++) dev[i] = (uint8_t)('A' + i % 26);
    host_i2c_feed(dev, sizeof(dev));
    TwoWire w(0);
    check("wire_begin", w.begin());
    w.beginTransmission(0x50); w.write((uint8_t)0x00); check("wire_end_tx_ok", w.endTransmission() == 0);
    check("wire_request_4", w.requestFrom((uint8_t)0x50, (size_t)4) == 4 && w.available() == 4);
    std::string got; while (w.available()) got.push_back((char)w.read());
    check("wire_read_bytes", got == "ABCD", got);
    size_t n = w.requestFrom((uint8_t)0x50, (size_t)500);
    check("wire_request_clamped", n == 128 && w.available() == 128, std::to_string(n));
    check("wire_read_after_clamp", w.read() == 'E');
    w.end(); }

  // ---- ArduinoOTA ----
  for (int variant = 0; variant < 2; variant++) {
    host_reset_clock(); host_net_reset(); host_udp_queue_reset();
    const char *inv = "0 3232 5 5d41402abc4b2a76b9719d911017c592\n";
    host_udp_queue((const uint8_t *)inv, strlen(inv));
    const char *fw = variant ? "hellX" : "hello";
    host_net_set_incoming((const uint8_t *)fw, 5);
    bool ended = false; int err = -1;
    ArduinoOTAClass ota(&Update);
    ota.setRebootOnSuccess(false); ota.setMdnsEnabled(false); ota.setTimeout(50);
    ota.onEnd([&]() { ended = true; }); ota.onError([&](ota_error_t e) { err = (int)e; });
    ota.begin(); ota.handle();
    check(variant ? "ota_invite_ok_reply_2" : "ota_invite_ok_reply", host_udp_last_reply() == "OK", host_udp_last_reply());
    ota.handle();
    if (!variant) check("ota_update_completes", ended && err == -1 && contains(host_net_last_tx(), "OK"), host_net_last_tx());
    else check("ota_md5_mismatch_rejected", !ended && err == OTA_END_ERROR, std::to_string(err));
    ota.end(); }

  printf("SUMMARY passed=%d failed=%d\n", g_pass, g_fail);
  return g_fail ? 1 : 0;
}
