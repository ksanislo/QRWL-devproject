#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>

#define WIDTH 400
#define HEIGHT 240
#define WAIT_TIMEOUT 300000000ULL
#define AUTOLOADER_FILE "autoloader.url"
#define AUTOLOADER_URL "http://3ds.intherack.com/files/AutoLoader.cia"
#define AUTOLOADER_TITLEID 0x000400000b198200
#define TITLEID 0x000400000b198000

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

bool onProgress(u64 pos, u64 size);
