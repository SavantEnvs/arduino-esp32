// Fuzz target: libraries/WebServer — one HTTP request, as received by a sketch.
//
// The input is the raw byte stream a TCP peer sends to the server. A fresh
// WebServer is created per input with the handlers a typical sketch registers
// (plain route, UriBraces/UriGlob path args, POST form + multipart upload,
// raw body, Basic/Digest auth, CORS/auth middleware, header collection), the
// host NetworkServer hands it one connection carrying the input, and
// handleClient() runs exactly as in loop(): request line, headers, url-decoding,
// query/form/multipart parsing, chunked raw bodies and auth headers are all
// parsed by the upstream code (Parsing.cpp / WebServer.cpp).
#include <Arduino.h>
#include <WebServer.h>
#include <uri/UriBraces.h>
#include <uri/UriGlob.h>
#include <Middlewares.h>
#include "NetworkClient.h"

static void consumeRequest(WebServer &s) {
  // Touch everything the parser produced, as a handler would.
  String acc = s.uri();
  for (int i = 0; i < s.args(); i++) { acc += s.argName(i); acc += s.arg(i); }
  for (int i = 0; i < s.headers(); i++) { acc += s.headerName(i); acc += s.header(i); }
  acc += s.hostHeader();
  acc += s.version();
  if (s.hasArg("plain")) acc += s.arg("plain");
  s.send(200, "text/plain", acc);
}

static int run_one(const uint8_t *data, size_t size) {
  host_reset_clock();
  host_net_reset();
  WebServer *server = new WebServer(80);
  WebServer &s = *server;
  const char *keys[] = {"User-Agent", "Cookie", "If-None-Match", "X-Test"};
  s.collectHeaders(keys, 4);
  s.on("/", [&]() { consumeRequest(s); });
  s.on(UriBraces("/users/{}/posts/{}"), [&]() {
    String r = s.pathArg(0) + "/" + s.pathArg(1);
    s.send(200, "text/plain", r);
  });
  s.on(UriGlob("/glob/*/x?"), [&]() { consumeRequest(s); });
  s.on("/basic", [&]() {
    if (!s.authenticate("admin", "secret")) return s.requestAuthentication(BASIC_AUTH);
    s.send(200, "text/plain", "ok");
  });
  s.on("/digest", [&]() {
    if (!s.authenticate("admin", "secret")) return s.requestAuthentication(DIGEST_AUTH, "realm");
    s.send(200, "text/plain", "ok");
  });
  s.on("/sha1", [&]() {
    if (!s.authenticateBasicSHA1("admin", "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4")) return s.requestAuthentication();
    s.send(200, "text/plain", "ok");
  });
  s.on(
    "/upload", HTTP_POST, [&]() { s.send(200, "text/plain", "done"); },
    [&]() {
      HTTPUpload &u = s.upload();
      volatile size_t sink = u.filename.length() + u.name.length() + u.type.length() + u.currentSize;
      (void)sink;
    }
  );
  s.on("/raw", HTTP_PUT, [&]() { s.send(200); }, [&]() {
    HTTPRaw &r = s.raw();
    volatile size_t sink = r.currentSize + r.totalSize;
    (void)sink;
  });
  s.on("/chunk", [&]() {
    s.chunkResponseBegin();
    s.chunkWrite("a", 1);
    s.chunkResponseEnd();
  });
  s.onNotFound([&]() { consumeRequest(s); });
  CorsMiddleware *cors = new CorsMiddleware();
  cors->setOrigin("*").setMethods("GET,POST").setHeaders("X-Test").setAllowCredentials(false).setMaxAge(60);
  s.addMiddleware(cors);
  s.begin();

  host_net_set_incoming(data, size);
  // One connection; handleClient() returns to HC_NONE once it has answered.
  for (int i = 0; i < 4; i++) s.handleClient();
  s.close();
  delete server;
  delete cors;
  host_net_reset();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return run_one(data, size);
}
