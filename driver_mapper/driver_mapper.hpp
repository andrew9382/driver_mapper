#pragma once

#define RELOC_FLAG64(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG32(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_HIGHLOW)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

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

	struct MEMSET_IN_KERNEL_STRUCT
	{
		SIZE_T size;
		int value;
		ULONGLONG kernel_address;
	};

	struct READ_WRITE_MEMORY_STRUCT
	{
		ULONGLONG src;
		ULONGLONG dst;
		SIZE_T size;
	};

	struct FIND_EXPORTED_ROUTINE_BY_NAME_STRUCT
	{
		char name[MAX_PATH];
		PVOID module_base;
		ULONGLONG ret_address;
	};

	bool LoadDriver(std::filesystem::path& path_to_driver);

	ULONGLONG GetSystemRoutineAddress(const wchar_t* routine_name);
	ULONGLONG AllocatePool(kernel::POOL_TYPE pool_type, SIZE_T size);
	ULONGLONG FindExportedRoutineByName(ULONGLONG module_base, const char* routine_name);
	bool FreePool(ULONGLONG pool_address);
	bool MemsetInKernel(ULONGLONG kernel_addr, SIZE_T size, int value);
	bool WriteMemory(ULONGLONG src, ULONGLONG dst, SIZE_T size);

	bool ResolveRelocsByDelta(BYTE* image_base, IMAGE_OPTIONAL_HEADER* opt_header, ULONGLONG delta);
	bool ResolveImports(BYTE* image_base, IMAGE_OPTIONAL_HEADER* opt_header);

	ULONGLONG GetKernelModuleAddress(const char* module_name);

	namespace shellcode_funcs
	{
		void __stdcall GetSystemRoutineAddress(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_routine_data);
		void __stdcall AllocatePool(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_pool_data);
		void __stdcall FreePool(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_pool);
		void __stdcall MemsetInKernel(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_memset_data);
		void __stdcall WriteMemory(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_write_mem_data);
		void __stdcall FindExportedRoutineByName(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_routine_data);

		// for test
		//void __stdcall PrintHelloWorldKernel(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress);
	}
}