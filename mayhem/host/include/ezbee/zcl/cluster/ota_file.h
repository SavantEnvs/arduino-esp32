// Host stand-in for esp-zigbee-sdk's ezbee/zcl/cluster/ota_file.h (prebuilt SDK,
// not available on a host). Only the OTA file header layout the parser fills:
// the Zigbee Cluster Library OTA Upgrade file header (ZCL spec 11.4.2), packed,
// and the header field-control bits for the optional fields.
#pragma once
#include <stdint.h>
typedef uint8_t ezb_extaddr_t[8];
#define EZB_ZCL_OTA_FILE_HEADER_FC_SECURITY_CREDENTIAL_VERSION_PRESENT (1u << 0)
#define EZB_ZCL_OTA_FILE_HEADER_FC_DEVICE_SPECIFIC                     (1u << 1)
#define EZB_ZCL_OTA_FILE_HEADER_FC_HW_VERSION_PRESENT                  (1u << 2)
typedef struct {
  uint32_t file_id;          /* 0x0BEEF11E */
  uint16_t hdr_version;
  uint16_t hdr_length;
  uint16_t hdr_fc;
  uint16_t manufacturer_code;
  uint16_t image_type;
  uint32_t file_version;
  uint16_t stack_version;
  uint8_t hdr_string[32];
  uint32_t image_size;
} __attribute__((packed)) ezb_zcl_ota_file_header_t;
typedef struct {
  uint8_t security_credential_version;
  ezb_extaddr_t upgrade_file_destination;
  uint16_t minimum_hardware_version;
  uint16_t maximum_hardware_version;
} __attribute__((packed)) ezb_zcl_ota_file_header_optional_t;
