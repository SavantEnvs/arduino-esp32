// Host stand-in for the ESP32 ROM MD5 routines (a plain RFC 1321 MD5, host_md5.c).
#pragma once
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define ESP_ROM_MD5_DIGEST_LEN 16
typedef struct { uint32_t state[4]; uint32_t count[2]; uint8_t buffer[64]; } md5_context_t;
void esp_rom_md5_init(md5_context_t *ctx);
void esp_rom_md5_update(md5_context_t *ctx, const void *data, uint32_t len);
void esp_rom_md5_final(uint8_t *digest, md5_context_t *ctx);
#ifdef __cplusplus
}
#endif
