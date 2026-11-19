// Fuzz target: libraries/BLE — a received BLE advertisement, as a scanning
// sketch sees it (any device in radio range controls these bytes).
//
// Input: byte 0 = HCI advertising event type (low 3 bits) + flags, byte 1 =
// scan-response length, bytes 2..7 = advertiser address, then the advertising
// payload followed by the scan-response payload. The device record is built
// exactly as the NimBLE scan backend does it (BLEScan.nimble.cpp
// parseDiscEvent: fill address/type/flags, Impl::parsePayload(), mint the
// handle via BLEScanImplCommon::makeAdvertisedDeviceHandle()), the scan
// response is merged as on SCAN_RSP, and then every public getter a sketch
// calls runs: name, UUIDs, service/manufacturer data, frame-type detection and
// the iBeacon / Eddystone-URL / Eddystone-TLM decoders, toString().
//
// BLEScanImplCommon is the scan backend's (friend) helper; BLEScan itself needs
// the NimBLE host stack, so the harness supplies the two helper calls the
// backend makes, with the same bodies as scan/BLEScanImpl.h.
#include <Arduino.h>
#include "scan/BLEAdvertisedDeviceImpl.h"
#include "advertising/BLEBeacon.h"
#include "advertising/BLEEddystone.h"

struct BLEScanImplCommon {
  static BLEAdvertisedDevice makeAdvertisedDeviceHandle(std::shared_ptr<BLEAdvertisedDevice::Impl> impl) {
    return BLEAdvertisedDevice(std::move(impl));
  }
  static void mergeScanResponse(BLEAdvertisedDevice &d, const uint8_t *data, size_t len, int8_t rssi) {
    d.mergeScanResponse(data, len, rssi);
  }
};

static size_t use(const String &s) { return s.length(); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return -1;
  const uint8_t evt = data[0];
  size_t rspLen = data[1];
  const uint8_t *addr = data + 2;
  data += 8; size -= 8;
  if (rspLen > size) rspLen = size;
  const size_t advLen = size - rspLen;

  auto impl = std::make_shared<BLEAdvertisedDevice::Impl>();
  impl->address = BTAddress(addr, static_cast<BTAddress::Type>((evt >> 3) & 3));
  impl->addrType = static_cast<BTAddress::Type>((evt >> 3) & 3);
  impl->rssi = -60;
  impl->hasRSSI = true;
  switch (evt & 7) {
    case 0: impl->connectable = impl->scannable = true; impl->advType = BLEAdvType::ConnectableScannable; break;
    case 1: impl->connectable = impl->directed = true; impl->advType = BLEAdvType::ConnectableDirected; break;
    case 2: impl->scannable = true; impl->advType = BLEAdvType::ScannableUndirected; break;
    case 3: impl->advType = BLEAdvType::NonConnectable; break;
    default: break;
  }
  if (advLen > 0) impl->parsePayload(data, advLen);
  BLEAdvertisedDevice dev = BLEScanImplCommon::makeAdvertisedDeviceHandle(impl);
  if (rspLen > 0 && (evt & 0x20)) BLEScanImplCommon::mergeScanResponse(dev, data + advLen, rspLen, -61);

  volatile size_t sink = 0;
  sink += use(dev.getName()) + use(dev.getAddress().toString()) + dev.getTXPower() + dev.getAppearance();
  sink += dev.getMinPreferred() + dev.getMaxPreferred();
  size_t mlen = 0;
  const uint8_t *m = dev.getManufacturerData(&mlen);
  if (m && mlen) sink += m[0] + m[mlen - 1];
  sink += use(dev.getManufacturerDataString()) + dev.getManufacturerCompanyId();
  for (size_t i = 0; i < dev.getServiceUUIDCount(); i++) sink += use(dev.getServiceUUID(i).toString());
  sink += dev.isAdvertisingService(BLEUUID((uint16_t)0xFEAA));
  for (size_t i = 0; i < dev.getServiceDataCount(); i++) {
    size_t l = 0;
    const uint8_t *sd = dev.getServiceData(i, &l);
    if (sd && l) sink += sd[0] + sd[l - 1];
    sink += use(dev.getServiceDataString(i)) + use(dev.getServiceDataUUID(i).toString());
  }
  sink += dev.getPayloadLength();
  switch (dev.getFrameType()) {
    default: break;
  }
  BLEBeacon beacon;
  if (dev.getBeacon(beacon)) {
    sink += beacon.getMajor() + beacon.getMinor() + beacon.getManufacturerId() + beacon.getSignalPower();
    sink += use(beacon.getProximityUUID().toString());
    BLEAdvertisementData ad = beacon.getAdvertisementData();
    (void)ad;
  }
  BLEEddystoneURL url;
  if (dev.getEddystoneURL(url)) {
    String u = url.getURL();
    sink += use(u) + url.getTxPower();
    BLEEddystoneURL again;
    again.setURL(u);  // re-encode what was decoded, as a repeater sketch would
    BLEAdvertisementData ad = again.getAdvertisementData();
    (void)ad;
  }
  BLEEddystoneTLM tlm;
  if (dev.getEddystoneTLM(tlm)) {
    sink += tlm.getBatteryVoltage() + tlm.getAdvertisingCount() + tlm.getUptime() + (int)tlm.getTemperature();
    sink += use(tlm.toString());
  }
  sink += use(dev.toString());
  if (evt & 0x40) {
    // The advertised name, as text, through the UUID / address parsers (sketches
    // build BLEUUID/BTAddress from strings received over the air).
    String name = dev.getName();
    sink += use(BLEUUID(name.c_str()).toString());
    sink += use(BTAddress(name).toString());
  }
  (void)sink;
  return 0;
}
