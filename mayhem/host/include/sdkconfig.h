// Host stand-in for the ESP-IDF generated sdkconfig.h (fuzz build only).
#pragma once
#define CONFIG_IDF_TARGET_ESP32S3 1
#define CONFIG_IDF_TARGET "esp32s3"
#define CONFIG_LWIP_IPV6 1
#define CONFIG_FREERTOS_HZ 1000
#define CONFIG_ARDUHAL_LOG_DEFAULT_LEVEL 0
// BLE: build the NimBLE-flavoured, observer-capable stack-neutral parsers.
#define CONFIG_BT_ENABLED 1
#define CONFIG_NIMBLE_ENABLED 1
#define CONFIG_BT_NIMBLE_ENABLED 1
#define CONFIG_BT_NIMBLE_ROLE_OBSERVER 1
#define CONFIG_BT_NIMBLE_ROLE_BROADCASTER 1
