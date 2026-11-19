#!/usr/bin/env bash
#
# mayhem/build.sh — host (Linux) fuzz build of arduino-esp32's input parsers.
#
# arduino-esp32 is an embedded framework: its real build cross-compiles for
# Xtensa/RISC-V against prebuilt ESP-IDF libraries, and nothing in it builds on
# a host. The parsers that read untrusted bytes (HTTP server/client, DNS,
# BLE advertisements, USB HID descriptors, IPv4/IPv6/MAC text, base64, ...) are
# plain C/C++ though, so this script compiles those upstream sources unmodified
# with clang + ASan/UBSan against a small host layer in mayhem/host/ (a stand-in
# Arduino.h, FreeRTOS/lwIP/sdkconfig headers, a virtual clock and in-memory
# sockets/UDP), and links one libFuzzer harness per entry point.
#
# Outputs: /mayhem/fuzz_<name> (libFuzzer) and /mayhem/fuzz_<name>-standalone
# (run-once reproducer), plus mayhem/build/test/host_selftest (normal flags) for
# mayhem/test.sh. Objects go to mayhem/build/ (gitignored). Re-runnable; offline.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS
cd "$SRC"

B="$SRC/mayhem/build"
H="$SRC/mayhem/host"
L="$SRC/libraries"
mkdir -p "$B"

# Include order: the host layer first (it shadows Network/AsyncUDP/sdkconfig/...),
# then the upstream core and the libraries under test. host_arduino.h is
# force-included so the real Arduino.h (FreeRTOS + SoC registers) is skipped
# even where upstream includes it as "Arduino.h" from inside cores/esp32.
INC=(-include "$H/include/host_arduino.h" -I"$H/include" -I"$SRC/cores/esp32"
     -I"$L/WebServer/src" -I"$L/HTTPClient/src" -I"$L/FS/src" -I"$L/Hash/src"
     -I"$L/DNSServer/src" -I"$L/NetBIOS/src" -I"$L/BLE/src" -I"$L/USB/src" -I"$L/Zigbee/src" -I"$L/Wire/src" -I"$L/ArduinoOTA/src")
DEFS=(-DCONFIG_ZB_ENABLED=1 -DHTTPCLIENT_NOSECURE -DHOST_FUZZ_BUILD=1)

# Sources by component (all upstream except mayhem/host/host_runtime.cpp).
CORE=(cores/esp32/WString.cpp cores/esp32/Print.cpp cores/esp32/Stream.cpp
      cores/esp32/StreamString.cpp cores/esp32/IPAddress.cpp cores/esp32/MacAddress.cpp
      cores/esp32/HEXBuilder.cpp cores/esp32/base64.cpp cores/esp32/MD5Builder.cpp cores/esp32/HashBuilder.cpp
      cores/esp32/BTAddress.cpp cores/esp32/stdlib_noniso.c
      cores/esp32/libb64/cdecode.c cores/esp32/libb64/cencode.c
      libraries/Hash/src/SHA1Builder.cpp libraries/Hash/src/SHA2Builder.cpp
      libraries/Hash/src/HMACBuilder.cpp libraries/FS/src/FS.cpp
      mayhem/host/host_runtime.cpp mayhem/host/host_wifi.cpp)
WEBSERVER=(libraries/WebServer/src/Parsing.cpp libraries/WebServer/src/WebServer.cpp
           libraries/WebServer/src/detail/mimetable.cpp
           libraries/WebServer/src/middleware/AuthenticationMiddleware.cpp
           libraries/WebServer/src/middleware/CorsMiddleware.cpp
           libraries/WebServer/src/middleware/LoggingMiddleware.cpp
           libraries/WebServer/src/middleware/MiddlewareChain.cpp)
HTTPCLIENT=(libraries/HTTPClient/src/HTTPClient.cpp)
BLE=(libraries/BLE/src/scan/BLEAdvertisedDevice.cpp libraries/BLE/src/scan/BLEAdvertisedDeviceImpl.cpp
     libraries/BLE/src/advertising/BLEBeacon.cpp libraries/BLE/src/advertising/BLEEddystone.cpp
     libraries/BLE/src/advertising/BLEAdvertisementData.cpp libraries/BLE/src/types/BLEUUID.cpp
     libraries/BLE/src/types/BLEAdvTypes.cpp)
DNSSERVER=(libraries/DNSServer/src/DNSServer.cpp)
NETBIOS=(libraries/NetBIOS/src/NetBIOS.cpp)
ZIGBEEOTA=(libraries/Zigbee/src/ZigbeeOTAFileParser.cpp)
WIRE=(libraries/Wire/src/Wire.cpp mayhem/host/host_i2c.cpp)
ARDUINOOTA=(libraries/ArduinoOTA/src/ArduinoOTA.cpp libraries/Hash/src/PBKDF2_HMACBuilder.cpp mayhem/host/host_ota.cpp)
USBHID=(libraries/USB/src/USBHIDReportMapParse.c)
USBKBD=(libraries/USB/src/USBHostHIDKeyboardDecode.cpp libraries/USB/src/keyboardLayout/KeyboardLayout_*.cpp)

# compile <variant> <flags...> -- <sources...>; prints the object list.
compile() {
  local variant="$1"; shift
  local flags=()
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  local objs=() src obj
  for src in "$@"; do
    obj="$B/$variant/${src%.*}.o"
    objs+=("$obj")
    mkdir -p "$(dirname "$obj")"
    case "$src" in
      *.c) echo "$CC -std=gnu11 ${flags[*]} ${DEFS[*]} ${INC[*]} -c $SRC/$src -o $obj" ;;
      *)   echo "$CXX -std=gnu++17 ${flags[*]} ${DEFS[*]} ${INC[*]} -c $SRC/$src -o $obj" ;;
    esac
  done > "$B/$variant.cmds"
  # Parallel compile; each line is one compiler invocation.
  tr '\n' '\0' < "$B/$variant.cmds" | xargs -0 -P "$MAYHEM_JOBS" -I{} sh -c '{}' >&2
  printf '%s\n' "${objs[@]}"
}

# UBSan's `enum` check is relaxed (only it; the rest of UBSan and ASan halt):
# WebServer's HTTP_ANY is `(HTTPMethod)255`, outside the range of the
# http_method enum, and every registered route stores and compares it, so the
# check fires on every request before any input is parsed.
RELAX=()
[ -z "$SANITIZER_FLAGS" ] || RELAX=(-fno-sanitize=enum)
FUZZ_FLAGS=($SANITIZER_FLAGS "${RELAX[@]}" $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -w)
ALL_SRCS=("${CORE[@]}" "${WEBSERVER[@]}" "${HTTPCLIENT[@]}" "${BLE[@]}" "${DNSSERVER[@]}" "${ZIGBEEOTA[@]}" "${WIRE[@]}" "${ARDUINOOTA[@]}" "${USBHID[@]}" "${USBKBD[@]}")
compile fuzz "${FUZZ_FLAGS[@]}" -- "${ALL_SRCS[@]}" > /dev/null
# NetBIOS.cpp's _getnbname() computes `(char - 'A') << 4`, a left shift of a
# negative value for any name byte below 'A' — UB that fires on nearly every
# query. Relaxed for that one file only (shift-base), so the target still runs
# the rest of the handler under halting ASan + UBSan.
compile fuzz "${FUZZ_FLAGS[@]}" -fno-sanitize=shift-base -- "${NETBIOS[@]}" > /dev/null
fobj() { local s o; for s in "$@"; do o="$B/fuzz/${s%.*}.o"; echo "$o"; done; }

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# harness <name> <component source arrays...>: links /mayhem/fuzz_<name>{,-standalone}.
harness() {
  local name="$1"; shift
  local hsrc="$SRC/mayhem/harnesses/fuzz_${name}.cpp"
  local objs; mapfile -t objs < <(fobj "$@")
  $CXX -std=gnu++17 "${FUZZ_FLAGS[@]}" "${DEFS[@]}" "${INC[@]}" -c "$hsrc" -o "$B/fuzz_${name}.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz_${name}.o" "${objs[@]}" "$B/lsan_off.o" -lm -o "$SRC/fuzz_${name}"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz_${name}.o" "${objs[@]}" "$B/lsan_off.o" "$B/standalone_main.o" -lm -o "$SRC/fuzz_${name}-standalone"
  echo "built fuzz_${name}"
}

harness core_text "${CORE[@]}"
harness webserver "${CORE[@]}" "${WEBSERVER[@]}"
harness httpclient "${CORE[@]}" "${HTTPCLIENT[@]}"
harness ble_advertisement "${CORE[@]}" "${BLE[@]}"
harness dnsserver "${CORE[@]}" "${DNSSERVER[@]}"
harness netbios "${CORE[@]}" "${NETBIOS[@]}"
harness zigbee_ota_file "${CORE[@]}" "${ZIGBEEOTA[@]}"
harness wire "${CORE[@]}" "${WIRE[@]}"
harness arduino_ota "${CORE[@]}" "${ARDUINOOTA[@]}"
harness usb_hid_report_map "${CORE[@]}" "${USBHID[@]}"
harness usb_hid_keyboard "${CORE[@]}" "${USBKBD[@]}"

# Functional self-test (mayhem/test/host_selftest.cpp): the same upstream sources
# with normal flags (no sanitizers, no fuzzer), run by mayhem/test.sh.
TEST_FLAGS=(-O1 -g -w $COVERAGE_FLAGS)
compile test "${TEST_FLAGS[@]}" -- "${ALL_SRCS[@]}" "${NETBIOS[@]}" mayhem/test/host_selftest.cpp > "$B/test.objs"
mapfile -t TOBJ < "$B/test.objs"
$CXX "${TEST_FLAGS[@]}" "${TOBJ[@]}" -lm -o "$B/host_selftest"
echo "built mayhem/build/host_selftest"
