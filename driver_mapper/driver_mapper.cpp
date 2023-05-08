#include "includes.hpp"

ULONGLONG driver_mapper::GetSystemRoutineAddress(const wchar_t* routine_name)
{
	if (!routine_name)
	{
		return 0;
	}
	
	ULONGLONG ret_address = 0;

	UNICODE_STRING us_name;

	RtlInitUnicodeString(&us_name, routine_name);

	if (!capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			ret_address = (ULONGLONG)MmGetSystemRoutineAddress(&us_name);

		}))
	{
		return 0;
	}

	return ret_address;
}

ULONGLONG driver_mapper::AllocatePool(kernel::POOL_TYPE pool_type, SIZE_T size)
{
	ULONGLONG ret_address = 0;

	UNICODE_STRING ExAllocatePool_us;

	RtlInitUnicodeString(&ExAllocatePool_us, L"ExAllocatePool");

	if (!capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			auto ExAllocatePool = (kernel::ExAllocatePool)MmGetSystemRoutineAddress(&ExAllocatePool_us);

			ret_address = (ULONGLONG)ExAllocatePool(pool_type, size);

		}))
	{
		return 0;
	}

	return ret_address;
}

ULONGLONG driver_mapper::FindExportedRoutineByName(ULONGLONG module_base, const char* routine_name)
{
	if (!routine_name)
	{
		return 0;
	}
	
	ULONGLONG ret_address;

	UNICODE_STRING RtlFindExportedRoutineByName_us;

	RtlInitUnicodeString(&RtlFindExportedRoutineByName_us, L"RtlFindExportedRoutineByName");

	if (!capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			auto RtlFindExportedRoutineByName = (kernel::RtlFindExportedRoutineByName)MmGetSystemRoutineAddress(&RtlFindExportedRoutineByName_us);

			ret_address = (ULONGLONG)RtlFindExportedRoutineByName((PVOID)module_base, (PCHAR)routine_name);

		}))
	{
		return 0;
	}

	return ret_address;
}

bool driver_mapper::FreePool(ULONGLONG pool_address)
{
	UNICODE_STRING ExFreePool_us;

	RtlInitUnicodeString(&ExFreePool_us, L"ExFreePool");

	return capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			auto ExFreePool = (kernel::ExFreePool)MmGetSystemRoutineAddress(&ExFreePool_us);

			ExFreePool((PVOID)pool_address);
		
		});
}

bool driver_mapper::MemsetInKernel(ULONGLONG kernel_addr, SIZE_T size, int value)
{
	UNICODE_STRING memset_us;

	RtlInitUnicodeString(&memset_us, L"memset");
	
	return capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			auto _memset = (decltype(memset)*)MmGetSystemRoutineAddress(&memset_us);

			_memset((PVOID)kernel_addr, value, size);

		});
}

bool driver_mapper::KernelCopyMemory(PVOID src, PVOID dst, SIZE_T size)
{
	UNICODE_STRING RtlCopyMemory_us;

	RtlInitUnicodeString(&RtlCopyMemory_us, L"RtlCopyMemory");

	return capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			auto _RtlCopyMemory = (kernel::RtlCopyMemory)MmGetSystemRoutineAddress(&RtlCopyMemory_us);

			_RtlCopyMemory(dst, src, size);

		});
}

NTSTATUS driver_mapper::StartDriverEntry(DriverEntry driver_entry, PVOID p_driver_object, PVOID p_registry_path)
{
	NTSTATUS ret_status;

	capcom.ExecuteUserFunction([&](kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
		{
			ret_status = driver_entry(p_driver_object, p_registry_path);

		});
	
	return ret_status;
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

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		auto* reloc_data = (IMAGE_BASE_RELOCATION*)(image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		while (reloc_data->VirtualAddress)
		{
			DWORD amount_of_entries = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relative_info = (WORD*)(reloc_data + 1);

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
		auto* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

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
				if (IMAGE_SNAP_BY_ORDINAL(p_thunk->u1.Ordinal))
				{
					LOG("[-] Can't get exported function name");

					return false;
				}

				auto* imp_by_name = (IMAGE_IMPORT_BY_NAME*)(image_base + p_thunk->u1.AddressOfData);

				char* func_name = (char*)imp_by_name->Name;

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

	DriverEntry driver_entry = (DriverEntry)(kernel_image_base + opt_header->AddressOfEntryPoint);

	if (!NT_SUCCESS(StartDriverEntry(driver_entry, 0, (PVOID)kernel_image_base)))
	{
		LOG("[-] Can't execute driver entry");
		
		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}

	LOG("[+] Driver entry executed!");

	LOG("[>] Erasing headers...");

	if (!MemsetInKernel(kernel_image_base, opt_header->SizeOfHeaders, 0))
	{
		LOG("[-] Can't erase headers");

		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}

	LOG("[+] Headers erased!");
	
	VirtualFree(local_image, 0, MEM_RELEASE);

	return true;
}
