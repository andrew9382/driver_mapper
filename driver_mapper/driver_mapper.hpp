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
	using DriverEntry = NTSTATUS (__cdecl*) (PVOID p_driver_object, PVOID p_registry_path);

	bool LoadDriver(std::filesystem::path& path_to_driver);

	ULONGLONG GetSystemRoutineAddress(const wchar_t* routine_name);
	ULONGLONG AllocatePool(kernel::POOL_TYPE pool_type, SIZE_T size);
	ULONGLONG FindExportedRoutineByName(ULONGLONG module_base, const char* routine_name);
	bool FreePool(ULONGLONG pool_address);
	bool MemsetInKernel(ULONGLONG kernel_addr, SIZE_T size, int value);
	bool KernelCopyMemory(PVOID src, PVOID dst, SIZE_T size);
	NTSTATUS StartDriverEntry(DriverEntry driver_entry, PVOID p_driver_object, PVOID p_registry_path);

	bool ResolveRelocsByDelta(BYTE* image_base, IMAGE_OPTIONAL_HEADER* opt_header, ULONGLONG delta);
	bool ResolveImports(BYTE* image_base, IMAGE_OPTIONAL_HEADER* opt_header);

	ULONGLONG GetKernelModuleAddress(const char* module_name);
}