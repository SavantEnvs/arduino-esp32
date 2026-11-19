// Fuzz target: libraries/Wire TwoWire — a sketch talking to an I2C peripheral
// that returns attacker-chosen bytes (a malicious or faulty sensor/EEPROM, or a
// spoofed device on an exposed bus), with the sketch's own sequence of calls.
//
// Input: a byte-coded sequence of TwoWire calls (setBufferSize, begin/end,
// beginTransmission/write/endTransmission, requestFrom with a 16-bit length,
// read/peek/readBytes/available, setClock/setTimeOut); the first byte is the
// length of the "device response" that follows it, which the host I2C HAL
// (host_i2c.cpp) hands out to i2cRead() as the peripheral's answer. The
// rx/tx buffer accounting and the requestFrom() clamp run as upstream wrote them.
#include <Arduino.h>
#include <Wire.h>

void host_i2c_feed(const uint8_t *data, size_t len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  size_t dev = data[0];
  data++; size--;
  if (dev > size) dev = size;
  host_reset_clock();
  host_i2c_feed(data, dev);
  const uint8_t *op = data + dev, *end = data + size;
  volatile size_t sink = 0;
  {
    TwoWire w(0);
    auto next = [&]() -> uint8_t { return op < end ? *op++ : 0; };
    while (op < end) {
      switch (next() % 12) {
        case 0: { size_t n = next(); n = (n << 8) | next(); sink += w.setBufferSize(n); break; }
        case 1: sink += w.begin(); break;
        case 2: w.beginTransmission(next() & 0x7f); break;
        case 3: { uint8_t b[64]; size_t n = next() % sizeof(b); for (size_t i = 0; i < n; i++) b[i] = next(); sink += w.write(b, n); break; }
        case 4: sink += w.write(next()); break;
        case 5: sink += w.endTransmission((bool)(next() & 1)); break;
        case 6: { uint8_t a = next() & 0x7f; size_t n = next(); n = (n << 8) | next(); sink += w.requestFrom(a, n, (bool)(next() & 1)); break; }
        case 7: sink += w.read() + w.peek() + w.available(); break;
        case 8: { uint8_t b[300]; size_t n = next() + 44; sink += w.readBytes(b, n); break; }
        case 9: w.setClock(100000u * (1 + (next() & 3))); sink += w.getClock(); break;
        case 10: w.setTimeOut(next()); sink += w.getTimeOut(); break;
        default: sink += w.end(); break;
      }
    }
    w.end();
  }
  (void)sink;
  return 0;
}
