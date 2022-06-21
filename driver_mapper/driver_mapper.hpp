#pragma once

namespace driver_mapper
{
	struct GET_ROUTINE_STRUCT
	{
		UNICODE_STRING routine_name;
		ULONGLONG ret_address;
	};

	struct ALLOCATE_POOL_STRUCT
	{
		kernel::POOL_TYPE pool_type;
		SIZE_T size;
		ULONGLONG ret_address;
	};

	bool LoadDriver(std::filesystem::path& path_to_driver);

	ULONGLONG GetSystemRoutineAddress(const wchar_t* routine_name);
	ULONGLONG AllocatePool(kernel::POOL_TYPE pool_type, SIZE_T size);
	bool FreePool(ULONGLONG pool_address);

	bool ResolveRelocsByDelta(BYTE* image_base, ULONGLONG delta);

	namespace shellcode_funcs
	{
		void __stdcall GetSystemRoutineAddress(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_routine_data);
		void __stdcall AllocatePool(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_pool_data);
		void __stdcall FreePool(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_pool);

		// for test
		//void __stdcall PrintHelloWorldKernel(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress);
	}
}