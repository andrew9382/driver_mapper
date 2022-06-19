#pragma once

#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <winternl.h>
#include "nt.hpp"
#include "defines.hpp"
#include "service.hpp"
#include "tools.hpp"
#include "kernel.hpp"
#include "capcom_bin.hpp"
#include "capcom.hpp"
#include "driver_mapper.hpp"