// Host stand-in: the fuzzed parsers run single-threaded, so only the handful of
// FreeRTOS types/macros the headers mention are provided.
#pragma once
#include <stdint.h>
typedef uint32_t TickType_t;
typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef void *SemaphoreHandle_t;
typedef void *QueueHandle_t;
typedef void *TaskHandle_t;
#define portMAX_DELAY ((TickType_t)0xffffffffUL)
#define portTICK_PERIOD_MS 1
#define pdMS_TO_TICKS(x) (x)
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
