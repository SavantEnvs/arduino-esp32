// Host stand-in for cores/esp32/esp32-hal-i2c.c: the I2C bus is a peripheral the
// harness controls. Writes are discarded; reads are filled from host_i2c_feed()
// (the attached device's bytes) and come up short when the device runs dry.
#include "host_arduino.h"
#include "esp32-hal-i2c.h"

static const uint8_t *g_rx;
static size_t g_rx_len;
static bool g_init[2];
static uint32_t g_clk[2];
void host_i2c_feed(const uint8_t *data, size_t len) { g_rx = data; g_rx_len = len; g_init[0] = g_init[1] = false; }

static size_t take(uint8_t *buff, size_t size) {
  size_t n = size < g_rx_len ? size : g_rx_len;
  if (n) memcpy(buff, g_rx, n);
  g_rx += n; g_rx_len -= n;
  return n;
}
extern "C" esp_err_t i2cInit(uint8_t n, int8_t, int8_t, uint32_t clk) { if (n > 1) return ESP_FAIL; g_init[n] = true; g_clk[n] = clk; return ESP_OK; }
extern "C" esp_err_t i2cDeinit(uint8_t n) { if (n > 1) return ESP_FAIL; g_init[n] = false; return ESP_OK; }
extern "C" esp_err_t i2cSetClock(uint8_t n, uint32_t f) { if (n > 1) return ESP_FAIL; g_clk[n] = f; return ESP_OK; }
extern "C" esp_err_t i2cGetClock(uint8_t n, uint32_t *f) { if (n > 1) return ESP_FAIL; *f = g_clk[n]; return ESP_OK; }
extern "C" esp_err_t i2cWrite(uint8_t n, uint16_t, const uint8_t *, size_t, uint32_t) { return (n < 2 && g_init[n]) ? ESP_OK : ESP_FAIL; }
extern "C" esp_err_t i2cRead(uint8_t n, uint16_t, uint8_t *buff, size_t size, uint32_t, size_t *readCount) {
  if (n > 1 || !g_init[n]) return ESP_FAIL;
  *readCount = take(buff, size);
  return *readCount == size ? ESP_OK : ESP_ERR_TIMEOUT;
}
extern "C" esp_err_t i2cWriteReadNonStop(uint8_t n, uint16_t a, const uint8_t *, size_t, uint8_t *rbuff, size_t rsize, uint32_t t, size_t *readCount) {
  return i2cRead(n, a, rbuff, rsize, t, readCount);
}
extern "C" bool i2cIsInit(uint8_t n) { return n < 2 && g_init[n]; }
extern "C" void *i2cBusHandle(uint8_t n) { return (n < 2 && g_init[n]) ? (void *)&g_init[n] : nullptr; }
