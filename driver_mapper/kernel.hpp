#pragma once

namespace kernel
{
    typedef enum _POOL_TYPE {
        NonPagedPool,
        NonPagedPoolExecute = NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed = NonPagedPool + 2,
        DontUseThisType,
        NonPagedPoolCacheAligned = NonPagedPool + 4,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
        MaxPoolType,
        NonPagedPoolBase = 0,
        NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
        NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
        NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
        NonPagedPoolSession = 32,
        PagedPoolSession = NonPagedPoolSession + 1,
        NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
        DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
        NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
        PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
        NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
        NonPagedPoolNx = 512,
        NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
        NonPagedPoolSessionNx = NonPagedPoolNx + 32,

    } POOL_TYPE;

    typedef struct _KPROCESS* PEPROCESS;

    typedef CCHAR KPROCESSOR_MODE;

    typedef enum _MODE {
        KernelMode,
        UserMode,
        MaximumMode
    } MODE;


	using DbgPrintEx                    = ULONG     (__cdecl*)      (ULONG, ULONG, PCSTR Format, ...);
	using MmGetSystemRoutineAddress     = PVOID     (__stdcall*)    (PUNICODE_STRING RoutineName);
    using ExAllocatePool                = PVOID     (__cdecl*)      (POOL_TYPE PoolType, SIZE_T NumberOfBytes);
    using ExFreePool                    = VOID      (__stdcall*)    (PVOID p);
    using RtlCopyMemory                 = VOID      (__cdecl*)      (PVOID Destination, CONST PVOID Source, SIZE_T Size);
    using RtlFindExportedRoutineByName  = PVOID     (__cdecl*)      (PVOID DllBase, PCHAR RoutineName);
}