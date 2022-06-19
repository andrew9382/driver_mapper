#pragma once

#define LOG(format, ...) printf(format"\n", __VA_ARGS__)

#define PRINT_USAGE() LOG("[ USAGE ] driver_mapper.exe <driver path>")

#define PAGE_SIZE 0x1000