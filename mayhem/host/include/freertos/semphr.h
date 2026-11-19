#pragma once
#include "freertos/FreeRTOS.h"
// Single-threaded host: mutexes are tokens that always succeed.
#define xSemaphoreCreateMutex()                ((SemaphoreHandle_t)1)
#define xSemaphoreCreateRecursiveMutex()       ((SemaphoreHandle_t)1)
#define xSemaphoreCreateBinary()               ((SemaphoreHandle_t)1)
#define xSemaphoreTake(s, t)                   (pdTRUE)
#define xSemaphoreGive(s)                      (pdTRUE)
#define xSemaphoreTakeRecursive(s, t)          (pdTRUE)
#define xSemaphoreGiveRecursive(s)             (pdTRUE)
#define vSemaphoreDelete(s)                    ((void)(s))
