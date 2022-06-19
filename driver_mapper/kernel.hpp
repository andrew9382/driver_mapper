#pragma once

namespace kernel
{
	using DbgPrintEx = ULONG (__cdecl*) (ULONG, ULONG, PCSTR Format, ...);
	using MmGetSystemRoutineAddress = PVOID (NTAPI*) (PUNICODE_STRING RoutineName);
}