#pragma once

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E

namespace nt
{
    enum class Privilege : int
    {
        SeCreateTokenPrivilege = 1,
        SeAssignPrimaryTokenPrivilege = 2,
        SeLockMemoryPrivilege = 3,
        SeIncreaseQuotaPrivilege = 4,
        SeUnsolicitedInputPrivilege = 5,
        SeMachineAccountPrivilege = 6,
        SeTcbPrivilege = 7,
        SeSecurityPrivilege = 8,
        SeTakeOwnershipPrivilege = 9,
        SeLoadDriverPrivilege = 10,
        SeSystemProfilePrivilege = 11,
        SeSystemtimePrivilege = 12,
        SeProfileSingleProcessPrivilege = 13,
        SeIncreaseBasePriorityPrivilege = 14,
        SeCreatePagefilePrivilege = 15,
        SeCreatePermanentPrivilege = 16,
        SeBackupPrivilege = 17,
        SeRestorePrivilege = 18,
        SeShutdownPrivilege = 19,
        SeDebugPrivilege = 20,
        SeAuditPrivilege = 21,
        SeSystemEnvironmentPrivilege = 22,
        SeChangeNotifyPrivilege = 23,
        SeRemoteShutdownPrivilege = 24,
        SeUndockPrivilege = 25,
        SeSyncAgentPrivilege = 26,
        SeEnableDelegationPrivilege = 27,
        SeManageVolumePrivilege = 28,
        SeImpersonatePrivilege = 29,
        SeCreateGlobalPrivilege = 30,
        SeTrustedCredManAccessPrivilege = 31,
        SeRelabelPrivilege = 32,
        SeIncreaseWorkingSetPrivilege = 33,
        SeTimeZonePrivilege = 34,
        SeCreateSymbolicLinkPrivilege = 35
    };

    typedef enum _SYSTEM_INFORMATION_CLASS {

        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemNextEventIdInformation,
        SystemEventIdsInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation,
        SystemPowerInformation,
        SystemProcessorSpeedInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemExtendedHandleInformation = 64

    } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    typedef struct _SYSTEM_HANDLE
    {
        PVOID Object;
        HANDLE UniqueProcessId;
        HANDLE HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE, * PSYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX
    {
        ULONG_PTR HandleCount;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

	using NtLoadDriver = NTSTATUS (__stdcall*) (PUNICODE_STRING DriverServiceName);
	using NtUnloadDriver = NTSTATUS (__stdcall*) (PUNICODE_STRING DriverServiceName);
	using RtlAdjustPrivilege = NTSTATUS (__stdcall*) (_In_ Privilege privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
}