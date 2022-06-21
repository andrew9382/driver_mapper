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

bool driver_mapper::FreePool(ULONGLONG pool_address)
{
	return capcom.ExecuteUserFunction(shellcode_funcs::FreePool, &pool_address);
}

bool driver_mapper::ResolveRelocsByDelta(BYTE* image_base, ULONGLONG delta)
{
	return false;
}

bool driver_mapper::LoadDriver(std::filesystem::path& path_to_driver)
{
	BYTE* file_raw = nullptr;
	size_t file_size = 0;

	if (!tools::MapFileToMemory(path_to_driver, &file_raw, &file_size))
	{
		return false;
	}

	auto dos_header = (IMAGE_DOS_HEADER*)file_raw;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		delete[] file_raw;

		return false;
	}

	auto nt_header = (IMAGE_NT_HEADERS*)(file_raw + dos_header->e_lfanew);

	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		delete[] file_raw;

		return false;
	}

	auto opt_header = (IMAGE_OPTIONAL_HEADER*)&nt_header->OptionalHeader;
	auto file_header = (IMAGE_FILE_HEADER*)&nt_header->FileHeader;

	if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		delete[] file_raw;

		return false;
	}

	BYTE* local_image = (BYTE*)VirtualAlloc(nullptr, opt_header->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!local_image)
	{
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

	ULONGLONG kernel_image_base = AllocatePool(kernel::NonPagedPool, opt_header->SizeOfImage);

	if (!ResolveRelocsByDelta(local_image, kernel_image_base - opt_header->ImageBase))
	{
		delete[] file_raw;
		
		VirtualFree(local_image, 0, MEM_RELEASE);

		FreePool(kernel_image_base);

		return false;
	}

	return true;
}