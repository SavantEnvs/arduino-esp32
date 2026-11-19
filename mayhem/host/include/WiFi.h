// Host stand-in for libraries/WiFi/src/WiFi.h: a soft-AP that is always up.
#pragma once
#include "Network.h"
typedef enum { WIFI_MODE_NULL = 0, WIFI_MODE_STA, WIFI_MODE_AP, WIFI_MODE_APSTA } wifi_mode_t;
#define WIFI_OFF   WIFI_MODE_NULL
#define WIFI_STA   WIFI_MODE_STA
#define WIFI_AP    WIFI_MODE_AP
#define WIFI_AP_STA WIFI_MODE_APSTA
class HostWiFiClass {
public:
  wifi_mode_t getMode() { return WIFI_MODE_AP; }
  IPAddress softAPIP() { return IPAddress(192, 168, 4, 1); }
  IPAddress localIP() { return IPAddress(192, 168, 4, 1); }
};
extern HostWiFiClass WiFi;
