#include "includes.hpp"

void __stdcall driver_mapper::shellcode_funcs::GetSystemRoutineAddress(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_routine_data)
{
	auto* routine_data = (GET_ROUTINE_STRUCT*)p_routine_data;

	routine_data->ret_address = (ULONGLONG)MmGetSystemRoutineAddress(&routine_data->routine_name);
}

void __stdcall driver_mapper::shellcode_funcs::AllocatePool(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_pool_data)
{
	UNICODE_STRING ExAllocatePool_us;

	RtlInitUnicodeString(&ExAllocatePool_us, L"ExAllocatePool");
	
	auto ExAllocatePool = (kernel::ExAllocatePool)MmGetSystemRoutineAddress(&ExAllocatePool_us);

	auto* pool_struct = (ALLOCATE_POOL_STRUCT*)p_pool_data;

	pool_struct->ret_address = (ULONGLONG)ExAllocatePool(pool_struct->pool_type, pool_struct->size);
}

void __stdcall driver_mapper::shellcode_funcs::FreePool(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_pool)
{
	UNICODE_STRING ExFreePool_us;

	RtlInitUnicodeString(&ExFreePool_us, L"ExFreePool");

	auto ExFreePool = (kernel::ExFreePool)MmGetSystemRoutineAddress(&ExFreePool_us);

	ExFreePool(*(void**)p_pool);
}

void __stdcall driver_mapper::shellcode_funcs::MemsetInKernel(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_memset_data)
{
	UNICODE_STRING memset_us;

	RtlInitUnicodeString(&memset_us, L"memset");
	
	auto _memset = (decltype(memset)*)MmGetSystemRoutineAddress(&memset_us);

	auto memset_data = (MEMSET_IN_KERNEL_STRUCT*)p_memset_data;

	_memset((void*)memset_data->kernel_address, memset_data->value, memset_data->size);
}

void __stdcall driver_mapper::shellcode_funcs::_CopyMemory(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_write_mem_data)
{
	UNICODE_STRING RtlCopyMemory_us;

	RtlInitUnicodeString(&RtlCopyMemory_us, L"RtlCopyMemory");

	auto _RtlCopyMemory = (kernel::RtlCopyMemory)MmGetSystemRoutineAddress(&RtlCopyMemory_us);

	auto* write_mem_data = (READ_WRITE_MEMORY_STRUCT*)p_write_mem_data;

	_RtlCopyMemory(write_mem_data->dst, write_mem_data->src, write_mem_data->size);
}

void __stdcall driver_mapper::shellcode_funcs::FindExportedRoutineByName(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID p_routine_data)
{
	UNICODE_STRING RtlFindExportedRoutineByName_us;

	RtlInitUnicodeString(&RtlFindExportedRoutineByName_us, L"RtlFindExportedRoutineByName");

	auto RtlFindExportedRoutineByName = (kernel::RtlFindExportedRoutineByName)MmGetSystemRoutineAddress(&RtlFindExportedRoutineByName_us);

	auto* routine_data = (FIND_EXPORTED_ROUTINE_BY_NAME_STRUCT*)p_routine_data;

	routine_data->ret_address = (ULONGLONG)RtlFindExportedRoutineByName(routine_data->module_base, routine_data->name);
}

// for test
/*void __stdcall driver_mapper::shellcode_funcs::PrintHelloWorldKernel(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
{
	UNICODE_STRING us;

	RtlInitUnicodeString(&us, L"DbgPrintEx");

	kernel::DbgPrintEx DbgPrintEx = (kernel::DbgPrintEx)MmGetSystemRoutineAddress(&us);

	DbgPrintEx(0, 0, "Hello World!\n");
}*/

ULONGLONG driver_mapper::GetSystemRoutineAddress(const wchar_t* routine_name)
{
	if (!routine_name)
	{
		return 0;
	}
	
	GET_ROUTINE_STRUCT routine_data;

	RtlInitUnicodeString(&routine_data.routine_name, routine_name);

	if (!capcom.ExecuteUserFunction(shellcode_funcs::GetSystemRoutineAddress, &routine_data))
	{
		return 0;
	}

	return routine_data.ret_address;
}

ULONGLONG driver_mapper::AllocatePool(kernel::POOL_TYPE pool_type, SIZE_T size)
{
	ALLOCATE_POOL_STRUCT pool;

	pool.pool_type = pool_type;
	pool.size = size;

	if (!capcom.ExecuteUserFunction(shellcode_funcs::AllocatePool, &pool))
	{
		return 0;
	}

	return pool.ret_address;
}

ULONGLONG driver_mapper::FindExportedRoutineByName(ULONGLONG module_base, const char* routine_name)
{
	if (!routine_name)
	{
		return 0;
	}
	
	FIND_EXPORTED_ROUTINE_BY_NAME_STRUCT routine_data;

	routine_data.module_base = (PVOID)module_base;
	strcpy_s(routine_data.name, routine_name);

	if (!capcom.ExecuteUserFunction(shellcode_funcs::FindExportedRoutineByName, &routine_data))
	{
		return 0;
	}

	return routine_data.ret_address;
}

bool driver_mapper::FreePool(ULONGLONG pool_address)
{
	return capcom.ExecuteUserFunction(shellcode_funcs::FreePool, &pool_address);
}

bool driver_mapper::MemsetInKernel(ULONGLONG kernel_addr, SIZE_T size, int value)
{
	MEMSET_IN_KERNEL_STRUCT memset_data;

	memset_data.kernel_address = kernel_addr;
	memset_data.size = size;
	memset_data.value = value;

	return capcom.ExecuteUserFunction(shellcode_funcs::MemsetInKernel, &memset_data);
}

bool driver_mapper::KernelCopyMemory(PVOID src, PVOID dst, SIZE_T size)
{
	READ_WRITE_MEMORY_STRUCT write_mem_data;

	write_mem_data.src = src;
	write_mem_data.dst = dst;
	write_mem_data.size = size;

	return capcom.ExecuteUserFunction(shellcode_funcs::_CopyMemory, &write_mem_data);
}

bool driver_mapper::ResolveRelocsByDelta(BYTE* image_base, IMAGE_OPTIONAL_HEADER* opt_header, ULONGLONG delta)
{
	if (!image_base || !opt_header)
	{
		return false;
	}

	if (!delta)
	{
		return true;
	}

	if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		return false;
	}

	auto reloc_data = (IMAGE_BASE_RELOCATION*)(image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (reloc_data->VirtualAddress)
	{
		DWORD amount_of_entries = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* relative_info = (WORD*)reloc_data + 1;

		for (DWORD i = 0; i < amount_of_entries; ++i, ++relative_info)
		{
			if (RELOC_FLAG(*relative_info))
			{
				ULONG_PTR* patch = (ULONG_PTR*)(image_base + reloc_data->VirtualAddress + (*relative_info & 0xFFF));
				*patch += delta;
			}
		}

		reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_data + reloc_data->SizeOfBlock);
	}

	return true;
}

bool driver_mapper::ResolveImports(BYTE* image_base, IMAGE_OPTIONAL_HEADER* opt_header)
{
	if (!image_base || !opt_header)
	{
		return false;
	}

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (import_descriptor->Name)
		{
			char* module_name = (char*)(image_base + import_descriptor->Name);

			ULONGLONG module_base = GetKernelModuleAddress(module_name);

			if (!module_base)
			{
				LOG("[-] Can't get base address of '%s' module", module_name);

				return false;
			}

			auto* p_thunk = (IMAGE_THUNK_DATA*)(image_base + import_descriptor->OriginalFirstThunk);
			auto* p_func = (IMAGE_THUNK_DATA*)(image_base + import_descriptor->FirstThunk);

			for (; p_thunk->u1.AddressOfData; ++p_thunk, ++p_func)
			{
				auto* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(image_base + p_thunk->u1.AddressOfData);

				char* func_name = (char*)imp_by_name->Name;

				if (!func_name)
				{
					LOG("[-] Can't get exported function name");

					return false;
				}

				p_func->u1.Function = FindExportedRoutineByName(module_base, func_name);

				if (!p_func->u1.Function)
				{
					LOG("[-] Can't get address of function: %s", func_name);

					return false;
				}
			}

			++import_descriptor;
		}
	}

	return true;
}

ULONGLONG driver_mapper::GetKernelModuleAddress(const char* module_name)
{
	void* buffer = nullptr;
	ULONG buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (buffer)
		{
			delete[] buffer;
		}

		buffer = new BYTE[buffer_size];

		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status))
	{
		if (buffer)
		{
			delete[] buffer;
		}

		return 0;
	}

	auto* modules = (nt::RTL_PROCESS_MODULES*)buffer;

	for (DWORD i = 0; i < modules->NumberOfModules; ++i)
	{
		char* current_module_name = (char*)(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);

		if (!_strcmpi(current_module_name, module_name))
		{
			ULONGLONG address = (ULONGLONG)modules->Modules[i].ImageBase;
			
			delete[] buffer;

			return address;
		}
	}

	delete[] buffer;

	return 0;
}

bool driver_mapper::LoadDriver(std::filesystem::path& path_to_driver)
{
	LOG("[>] Mapping your driver...");

	BYTE* file_raw = nullptr;
	size_t file_size = 0;

	if (!tools::MapFileToMemory(path_to_driver, &file_raw, &file_size))
	{
		LOG("[-] Can't map file to memory");

		return false;
	}

	auto dos_header = (IMAGE_DOS_HEADER*)file_raw;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		LOG("[-] Dos signature doesn't match");

		delete[] file_raw;

		return false;
	}

	auto nt_header = (IMAGE_NT_HEADERS*)(file_raw + dos_header->e_lfanew);

	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		LOG("[-] NT signature doesn't match");

		delete[] file_raw;

		return false;
	}

	auto opt_header = (IMAGE_OPTIONAL_HEADER*)&nt_header->OptionalHeader;
	auto file_header = (IMAGE_FILE_HEADER*)&nt_header->FileHeader;

	if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		LOG("[-] Machine != AMD64");

		delete[] file_raw;

		return false;
	}

	LOG("[>] Allocating local image base...");

	BYTE* local_image = (BYTE*)VirtualAlloc(nullptr, opt_header->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!local_image)
	{
		LOG("[-] VirtualAlloc error: %d", GetLastError());

		delete[] file_raw;

		return false;
	}

	memcpy(local_image, file_raw, opt_header->SizeOfHeaders);

	auto* sec = IMAGE_FIRST_SECTION(nt_header);

	for (DWORD i = 0; i < file_header->NumberOfSections; ++i, ++sec)
	{
		if (sec->SizeOfRawData)
		{
			memcpy(local_image + sec->VirtualAddress, file_raw + sec->PointerToRawData, sec->SizeOfRawData);
		}
	}

	LOG("[+] Local image allocated!");

	delete[] file_raw;

	dos_header = (IMAGE_DOS_HEADER*)local_image;
	nt_header = (IMAGE_NT_HEADERS*)(local_image + dos_header->e_lfanew);
	file_header = (IMAGE_FILE_HEADER*)&nt_header->FileHeader;
	opt_header = (IMAGE_OPTIONAL_HEADER*)&nt_header->OptionalHeader;

	LOG("[>] Allocating kernel image base...");

	ULONGLONG kernel_image_base = AllocatePool(kernel::NonPagedPool, opt_header->SizeOfImage);

	if (!kernel_image_base)
	{
		LOG("[-] Can't allocate kernel image base");

		VirtualFree(local_image, 0, MEM_RELEASE);
		
		return false;
	}

	LOG("[+] Kernel image base allocated!");

	LOG("[>] Resolving relocations...");

	if (!ResolveRelocsByDelta(local_image, opt_header, kernel_image_base - opt_header->ImageBase))
	{
		LOG("[-] Can't resolve relocations");

		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}

	LOG("[+] Relocations resolved!");

	LOG("[>] Resolving imports...");

	if (!ResolveImports(local_image, opt_header))
	{
		LOG("[-] Can't resolve imports");

		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}

	LOG("[+] Imports resolved!");

	LOG("[>] Copying local image into kernel pool...");

	if (!KernelCopyMemory(local_image, (PVOID)kernel_image_base, opt_header->SizeOfImage))
	{
		LOG("[-] Can't copy local image into kernel pool");

		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}

	LOG("[+] Local image copied into kernel pool!");

	LOG("[>] Erasing headers...");

	if (!MemsetInKernel(kernel_image_base, opt_header->SizeOfHeaders, 0))
	{
		LOG("[-] Can't erase headers");

		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}
	
	LOG("[+] Headers erased!");

	FreePool(kernel_image_base); // temporary

	return true;
}