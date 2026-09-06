#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
using BYTE = uint8_t;
using WORD = uint16_t;
using DWORD = uint32_t;
using PVOID = void*;
#endif