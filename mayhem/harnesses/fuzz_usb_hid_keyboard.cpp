// Fuzz target: libraries/USB USBHostHIDKeyboardDecode.cpp — decoding of boot-
// protocol keyboard reports sent by an attached USB keyboard (untrusted device).
//
// Input: byte 0 picks the keyboard layout, byte 1 is the host's lock-LED state,
// byte 2 the output buffer capacity; then 8-byte boot reports follow
// (modifiers, reserved, keys[6]), each decoded as USBHostHIDKeyboard does:
// ASCII via the layout, then virtual-key / log names per key usage.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "USBHostHIDKeyboardDecode.h"

extern const uint8_t KeyboardLayout_en_US[];
extern const uint8_t KeyboardLayout_da_DK[];
extern const uint8_t KeyboardLayout_de_DE[];
extern const uint8_t KeyboardLayout_es_ES[];
extern const uint8_t KeyboardLayout_fr_CH[];
extern const uint8_t KeyboardLayout_fr_FR[];
extern const uint8_t KeyboardLayout_hu_HU[];
extern const uint8_t KeyboardLayout_it_IT[];
extern const uint8_t KeyboardLayout_ja_JP[];
extern const uint8_t KeyboardLayout_pt_BR[];
extern const uint8_t KeyboardLayout_pt_PT[];
extern const uint8_t KeyboardLayout_sv_SE[];

static const uint8_t *const kLayouts[] = {
  KeyboardLayout_en_US, KeyboardLayout_da_DK, KeyboardLayout_de_DE, KeyboardLayout_es_ES,
  KeyboardLayout_fr_CH, KeyboardLayout_fr_FR, KeyboardLayout_hu_HU, KeyboardLayout_it_IT,
  KeyboardLayout_ja_JP, KeyboardLayout_pt_BR, KeyboardLayout_pt_PT, KeyboardLayout_sv_SE,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) return -1;
  const uint8_t *layout = kLayouts[data[0] % (sizeof(kLayouts) / sizeof(kLayouts[0]))];
  uint8_t leds = data[1];
  size_t cap = data[2] % 33;  // 0..32, the caller's buffer size
  data += 3; size -= 3;
  // The output buffer is exactly `cap` bytes on the heap so ASan sees overruns.
  char *buf = cap ? new char[cap] : nullptr;
  volatile size_t sink = 0;
  for (; size >= 8; data += 8, size -= 8) {
    const uint8_t mods = data[0];
    const uint8_t *keys = data + 2;
    sink += usbHostHidBootReportAppendAscii(buf, cap, mods, keys, leds, layout);
    for (int k = 0; k < 6; k++) {
      sink += (uint8_t)usbHostHidBootReportUsageToAscii(mods, keys[k], leds, layout);
      uint8_t vk = usbHostHidKeyboardUsageToArduinoVirtualKey(keys[k]);
      const char *n = usbHostHidArduinoVirtualKeyName(vk);
      if (n) sink += strlen(n);
      n = usbHostHidBootUsageLogName(keys[k]);
      if (n) sink += strlen(n);
    }
  }
  (void)sink;
  delete[] buf;
  return 0;
}
