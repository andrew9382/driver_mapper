#include "includes.hpp"

void __stdcall driver_mapper::PrintHelloWorldKernel(kernel::MmGetSystemRoutineAddress MmGetSystemRoutineAddress)
{
	UNICODE_STRING us;

	RtlInitUnicodeString(&us, L"DbgPrintEx");

	kernel::DbgPrintEx DbgPrintEx = (kernel::DbgPrintEx)MmGetSystemRoutineAddress(&us);

	DbgPrintEx(0, 0, "Hello World!\n");
}