// Fuzz target: libraries/HTTPClient — a sketch's GET against a hostile server.
//
// Input layout: the first line (up to '\n', at most 512 bytes) is the URL the
// sketch passes to HTTPClient::begin(client, url) (beginInternal URL parsing:
// scheme, user:pass@, host, port, path); everything after it is what the
// server sends back on the TCP connection. The response is parsed by the
// upstream code: status line, headers (collectHeaders, Location, Set-Cookie
// into the cookie jar, Transfer-Encoding: chunked, Content-Length), redirects
// (HTTPC_FORCE_FOLLOW_REDIRECTS) and the body through getString()/writeToStream().
// The server bytes may hold several responses separated by the line
// "\n--NEXT--\n": each one is served on the next TCP connection the client
// opens (the redirect targets).
#include <Arduino.h>
#include <HTTPClient.h>
#include <StreamString.h>
#include "NetworkClient.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t nl = 0;
  while (nl < size && nl < 512 && data[nl] != '\n') nl++;
  if (nl >= size || data[nl] != '\n') return -1;  // no URL line
  host_reset_clock();
  host_net_reset();
  String url;
  url.concat((const char *)data, nl);
  static const char kSep[] = "\n--NEXT--\n";
  const size_t sepLen = sizeof(kSep) - 1;
  const uint8_t *p = data + nl + 1, *end = data + size;
  for (;;) {
    const uint8_t *q = std::search(p, end, kSep, kSep + sepLen);
    host_net_set_incoming(p, (size_t)(q - p));
    if (q == end) break;
    p = q + sepLen;
  }

  CookieJar jar;
  {
    NetworkClient client;
    HTTPClient http;
    const char *keys[] = {"Content-Type", "Server", "Set-Cookie", "Location"};
    http.collectHeaders(keys, 4);
    http.setCookieJar(&jar);
    http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
    http.setRedirectLimit(3);
    http.setTimeout(100);
    http.setAuthorization("user", "pass");
    if (http.begin(client, url)) {
      int code = http.GET();
      String acc = HTTPClient::errorToString(code);
      for (int i = 0; i < http.headers(); i++) { acc += http.headerName(i); acc += http.header(i); }
      acc += http.getLocation();
      acc += http.getSize();
      if (code > 0) {
        if (data[0] & 1) {
          acc += http.getString();
        } else {
          StreamString sink;
          http.writeToStream(&sink);
        }
      }
      http.end();
    }
  }
  host_net_reset();
  return 0;
}
