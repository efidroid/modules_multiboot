/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _LIB_EFIVARS_H
#define _LIB_EFIVARS_H

#include <stdint.h>

#define EFI_GLOBAL_VARIABLE \
  { \
    0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } \
  }

#define EFI_EFIDROID_VARIABLE \
  { \
    0x7586a741, 0x84f7, 0x43d1, {0x82, 0x05, 0xda, 0x70, 0x69, 0xeb, 0x05, 0x4d } \
  }

#define EFI_VARIABLE_NON_VOLATILE               0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS         0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS             0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD      0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x00000010
#define EFI_VARIABLE_DEFAULT_ATTRIBUTES (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS)

#define EFIVARS_LOG_INTERNAL(fatal, log, x, fmt, ...) efivars_append_error((fatal), (log), (x), LOG_TAG, "%s:%u: error %d in %s: " fmt , SIMPLEFILENAME, __LINE__, (x), __func__, ##__VA_ARGS__ );
#define EFIVARS_LOG_TRACE(x, fmt, ...) EFIVARS_LOG_INTERNAL(0, 0, (x), fmt, ##__VA_ARGS__ );
#define EFIVARS_LOG_ERROR(x, fmt, ...) EFIVARS_LOG_INTERNAL(0, 1, (x), fmt, ##__VA_ARGS__ );
#define EFIVARS_LOG_FATAL(x, fmt, ...) EFIVARS_LOG_INTERNAL(1, 1, (x), fmt, ##__VA_ARGS__ );

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} efi_guid_t;

int efivar_dump(void);
int efivar_get(const char* name, efi_guid_t* guid,
               uint32_t* attributes, uint32_t* datasize, void* data);
int efivar_set(const char* name, efi_guid_t* guid,
               uint32_t attributes, uint32_t datasize, const void* data);

int efivar_get_global(const char* name, uint32_t* datasize, void* data);
int efivar_set_global(const char* name, uint32_t datasize, const void* data);

int efivar_get_efidroid(const char* name, uint32_t* datasize, void* data);
int efivar_set_efidroid(const char* name, uint32_t datasize, const void* data);

int efivars_report_error(const char* error);
int efivars_append_error(int fatal, int log, int error, const char* tag, const char* fmt, ...) __attribute__ ((format(printf, 5, 6)));

int efivars_report_errorbuf(void);
const char* efivars_get_errorbuf(void);
#endif
