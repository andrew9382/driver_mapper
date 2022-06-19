#pragma once

namespace nt
{

#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E

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

	using NtLoadDriver = NTSTATUS (__stdcall*) (PUNICODE_STRING DriverServiceName);
	using NtUnloadDriver = NTSTATUS (__stdcall*) (PUNICODE_STRING DriverServiceName);
	using RtlAdjustPrivilege = NTSTATUS (__stdcall*) (_In_ Privilege privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
}