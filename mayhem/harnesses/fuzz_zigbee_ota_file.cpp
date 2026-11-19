// Fuzz target: libraries/Zigbee ZigbeeOTAFileParser.cpp — the Zigbee OTA upgrade
// file a Zigbee end device downloads block by block from an OTA server (the
// server, or anyone spoofing it on the network, controls every byte).
//
// Input: bytes 0..3 = total image size the server announced (little endian),
// byte 4 = block size (1..255; the ZCL image-block payload size); the rest is
// the OTA file. The parser is driven exactly like ZigbeeHandlers.cpp's
// RECEIVING / CHECK progress callbacks: init(total), then per block setup()
// and process() until it stops returning ESP_ERR_NOT_FINISHED, consuming each
// element value as the handler does, and check() at the end.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include "ZigbeeOTAFileParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5) return -1;
  uint32_t total;
  memcpy(&total, data, 4);
  size_t block = data[4] ? data[4] : 1;
  data += 5; size -= 5;

  zb_ota_file_parser_t parser;
  zb_ota_file_parser_init(&parser, total);
  volatile uint32_t sink = 0;
  esp_err_t ret = ESP_OK;
  for (size_t off = 0; off < size && ret == ESP_OK; off += block) {
    // Each block in its own heap buffer of exactly its size, as the stack delivers it.
    size_t n = size - off < block ? size - off : block;
    std::vector<uint8_t> buf(data + off, data + off + n);
    zb_ota_file_parser_setup(&parser, (uint16_t)n, buf.data());
    do {
      esp_err_t pr = zb_ota_file_parser_process(&parser);
      if (pr != ESP_OK && pr != ESP_ERR_NOT_FINISHED) { ret = pr; break; }
      if (zb_ota_file_parser_is_element_value(&parser)) {
        if (parser.element.type != ZB_OTA_ELEMENT_UPGRADE_IMAGE) { ret = ESP_ERR_INVALID_ARG; break; }
        for (uint16_t i = 0; i < parser.element.length; i++) sink += parser.element.val[i];  // "esp_ota_write"
      }
      ret = pr;
    } while (ret == ESP_ERR_NOT_FINISHED);
    if (ret == ESP_ERR_NOT_FINISHED) ret = ESP_OK;
  }
  if (ret == ESP_OK) sink += zb_ota_file_parser_check(&parser);
  (void)sink;
  return 0;
}
