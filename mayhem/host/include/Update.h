// Host stand-in for libraries/Update/src/Update.h: an update sink in RAM. The
// real Updater writes esp_ota partitions; here begin() records the announced
// size, write() accepts bytes up to it and end() checks the MD5 the OTA client
// announced against what was received (same contract the OTA code relies on).
#pragma once
#include "host_arduino.h"
#include "MD5Builder.h"
#define U_FLASH    0
#define U_FLASHFS  100
#define U_SPIFFS   101
#define U_FATFS    102
#define U_LITTLEFS 103
#define U_AUTH     200
#define UPDATE_SIZE_UNKNOWN 0xFFFFFFFF
#ifndef LOW
#define LOW 0x0
#endif
class UpdaterVerifyClass;
class UpdateClass {
public:
  bool begin(size_t size = UPDATE_SIZE_UNKNOWN, int command = U_FLASH, int ledPin = -1, uint8_t ledOn = LOW, const char *label = NULL);
  size_t write(uint8_t *data, size_t len);
  bool end(bool evenIfRemaining = false);
  void abort() { _active = false; _error = "aborted"; }
  void printError(Print &out) { out.println(_error); }
  const char *errorString() { return _error; }
  bool setMD5(const char *expected_md5) { if (strlen(expected_md5) != 32) return false; _md5 = expected_md5; return true; }
  bool installSignature(UpdaterVerifyClass *) { return true; }
  bool isFinished() { return _active && _size != UPDATE_SIZE_UNKNOWN && _written == _size; }
  size_t progress() { return _written; }
  bool hasError() { return _error[0] != 0; }
private:
  bool _active = false;
  size_t _size = 0, _written = 0;
  const char *_error = "";
  String _md5;
  MD5Builder _hash;
};
extern UpdateClass Update;
