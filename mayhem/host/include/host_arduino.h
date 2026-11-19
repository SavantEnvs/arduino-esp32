// Host (Linux) stand-in for cores/esp32/Arduino.h, used ONLY by the fuzz build.
//
// The real Arduino.h pulls in FreeRTOS, the SoC register maps and the whole
// esp32-hal driver layer, none of which exist on a host. This header is
// force-included (-include host_arduino.h) into every translation unit: it
// defines the real header's include guards so a later #include "Arduino.h"
// (quoted, from inside cores/esp32) is a no-op, then provides the small part
// of the Arduino API the fuzzed parsers actually use. The parsers themselves
// (WString, Stream, IPAddress, WebServer, HTTPClient, BLE, ...) are compiled
// unmodified from the upstream tree.
#pragma once
#define Arduino_h 1
#define _ESP32_CORE_ARDUINO_H_ 1
#define HAL_ESP32_HAL_H_ 1
#define __ARDUHAL_LOG_H__ 1
#define ARDUINO 10812
#define ESP32 1
#define ARDUINO_ARCH_ESP32 1

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include "sdkconfig.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif
// Logging: compiled out (the real macros print to the UART at CORE_DEBUG_LEVEL).
#define ARDUHAL_LOG_LEVEL_NONE    (0)
#define ARDUHAL_LOG_LEVEL_ERROR   (1)
#define ARDUHAL_LOG_LEVEL_WARN    (2)
#define ARDUHAL_LOG_LEVEL_INFO    (3)
#define ARDUHAL_LOG_LEVEL_DEBUG   (4)
#define ARDUHAL_LOG_LEVEL_VERBOSE (5)
#define ARDUHAL_LOG_LEVEL ARDUHAL_LOG_LEVEL_NONE
#define CORE_DEBUG_LEVEL 0
#define host_log_noop(...) do { } while (0)
#define log_v(...) host_log_noop(__VA_ARGS__)
#define log_d(...) host_log_noop(__VA_ARGS__)
#define log_i(...) host_log_noop(__VA_ARGS__)
#define log_w(...) host_log_noop(__VA_ARGS__)
#define log_e(...) host_log_noop(__VA_ARGS__)
#define log_n(...) host_log_noop(__VA_ARGS__)
#define isr_log_v(...) host_log_noop(__VA_ARGS__)
#define isr_log_d(...) host_log_noop(__VA_ARGS__)
#define isr_log_i(...) host_log_noop(__VA_ARGS__)
#define isr_log_w(...) host_log_noop(__VA_ARGS__)
#define isr_log_e(...) host_log_noop(__VA_ARGS__)
#define log_buf_v(...) host_log_noop(__VA_ARGS__)
#define log_buf_d(...) host_log_noop(__VA_ARGS__)
#define log_buf_i(...) host_log_noop(__VA_ARGS__)
#define log_buf_w(...) host_log_noop(__VA_ARGS__)
#define log_buf_e(...) host_log_noop(__VA_ARGS__)
#define log_printf(...) 0
#define ESP_LOGE(tag, ...) host_log_noop(__VA_ARGS__)
#define ESP_LOGW(tag, ...) host_log_noop(__VA_ARGS__)
#define ESP_LOGI(tag, ...) host_log_noop(__VA_ARGS__)
#define ESP_LOGD(tag, ...) host_log_noop(__VA_ARGS__)
#define ESP_LOGV(tag, ...) host_log_noop(__VA_ARGS__)

#define ARDUINO_ISR_ATTR
#define IRAM_ATTR

// Time: a virtual clock. Every millis()/micros() call advances it, and delay()
// advances it by the requested amount, so the libraries' read/wait timeouts
// expire deterministically after a bounded number of polls instead of spinning
// on a host that never delivers more bytes. host_reset_clock() runs per input.
unsigned long millis(void);
unsigned long micros(void);
void delay(uint32_t ms);
void delayMicroseconds(uint32_t us);
void yield(void);
void host_reset_clock(void);
uint32_t esp_random(void);
long map(long, long, long, long, long);
#ifdef __cplusplus
}
#endif

#include "stdlib_noniso.h"
#include "binary.h"

#define PI         3.1415926535897932384626433832795
#define HALF_PI    1.5707963267948966192313216916398
#define TWO_PI     6.283185307179586476925286766559
#define DEG_TO_RAD 0.017453292519943295769236907684886
#define RAD_TO_DEG 57.295779513082320876798154814105
#define LSBFIRST 0
#define MSBFIRST 1
#ifndef __STRINGIFY
#define __STRINGIFY(a) #a
#endif
#define _min(a, b)                ((a) < (b) ? (a) : (b))
#define _max(a, b)                ((a) > (b) ? (a) : (b))
#define _abs(x)                   ((x) > 0 ? (x) : -(x))
#define constrain(amt, low, high) ((amt) < (low) ? (low) : ((amt) > (high) ? (high) : (amt)))
#define lowByte(w)  ((uint8_t)((w) & 0xff))
#define highByte(w) ((uint8_t)((w) >> 8))
#define bitRead(value, bit)            (((value) >> (bit)) & 0x01)
#define bitSet(value, bit)             ((value) |= (1UL << (bit)))
#define bitClear(value, bit)           ((value) &= ~(1UL << (bit)))
#define bitWrite(value, bit, bitvalue) ((bitvalue) ? bitSet(value, bit) : bitClear(value, bit))
#define bit(b) (1UL << (b))
#define _BV(b) (1UL << (b))
// Default I2C pins (from the board's pins_arduino.h).
#define SDA 8
#define SCL 9
typedef bool boolean;
typedef uint8_t byte;
typedef unsigned int word;

#ifdef __cplusplus
#include <algorithm>
#include <cmath>
#include "WCharacter.h"
#include "WString.h"
#include "Stream.h"
#include "Printable.h"
#include "Print.h"
#include "IPAddress.h"
#include "Client.h"
#include "Server.h"
#include "Udp.h"
using std::abs;
using std::isinf;
using std::isnan;
using std::max;
using std::min;
using std::round;
long random(long);
long random(long, long);
void randomSeed(unsigned long);

// Serial: a Print that discards everything (HTTPClient.cpp includes HardwareSerial.h).
class HostNullSerial : public Stream {
public:
  size_t write(uint8_t) override { return 1; }
  size_t write(const uint8_t *, size_t n) override { return n; }
  int available() override { return 0; }
  int read() override { return -1; }
  int peek() override { return -1; }
  void flush() override {}
  void begin(unsigned long) {}
};
extern HostNullSerial Serial;
#endif
