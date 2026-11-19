// Fuzz target: libraries/USB USBHIDReportMapParse.c — the HID report descriptor
// parser the USB host stack runs on the descriptor an attached (untrusted) USB
// device returns from GET_DESCRIPTOR. The whole input is the descriptor.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "USBHIDReportMapParse.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  usbhid_report_map_t *map = usbhid_parse_report_map(data, size);
  if (!map) return 0;
  volatile size_t sink = strlen(usbhid_usage_str(map->usage)) + map->appearance;
  for (uint8_t i = 0; i < map->reports_len; i++) {
    const usbhid_report_item_t &r = map->reports[i];
    sink += r.report_id + r.value_len + r.map_index;
    sink += strlen(usbhid_usage_str(r.usage));
    sink += strlen(usbhid_protocol_mode_str(r.protocol_mode));
    sink += strlen(usbhid_report_type_str(r.report_type));
  }
  (void)sink;
  usbhid_free_report_map(map);
  return 0;
}
