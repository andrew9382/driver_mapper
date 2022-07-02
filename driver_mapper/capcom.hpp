#pragma once

#define CAPCOM_IOCTL_X86 0xAA012044
#define CAPCOM_IOCTL_X64 0xAA013044

#define CAPCOM_INPUT_BUF_SIZE_X86 4
#define CAPCOM_INPUT_BUF_SIZE_X64 8

#define CAPCOM_OUTPUT_BUF_SIZE 4

#ifdef _WIN64
#define CAPCOM_IOCTL CAPCOM_IOCTL_X64

#define CAPCOM_INPUT_BUF_SIZE CAPCOM_INPUT_BUF_SIZE_X64
#else
#define CAPCOM_IOCTL CAPCOM_IOCTL_X86

#define CAPCOM_INPUT_BUF_SIZE CAPCOM_INPUT_BUF_SIZE_X86
#endif

using user_function = std::function<void(kernel::MmGetSystemRoutineAddress)>;

inline user_function* g_user_function = nullptr;

void CapcomDispatcher(kernel::MmGetSystemRoutineAddress mm_get_system_routine_address);

class CapcomControl
{
private:

	std::wstring driver_name = L"capcom.sys";
	std::wstring device_name = L"\\\\.\\Htsysm72FB";

	HANDLE device_handle = nullptr;

	std::filesystem::path driver_temp_path;

	bool ClearMmUnloadedDrivers();

public:

	bool ExecuteUserFunction(user_function p_func);

	bool Load();

	bool Unload();

} inline capcom;