#include "includes.hpp"

bool service::RegisterAndStart(const std::filesystem::path& path_to_driver)
{
    const DWORD service_type_kernel = 1;
    std::wstring service_path = L"SYSTEM\\CurrentControlSet\\Services\\capcom";
    std::wstring nt_path = L"\\??\\";
    nt_path += path_to_driver.c_str();

    HKEY service_hkey;
    if (RegCreateKey(HKEY_LOCAL_MACHINE, service_path.c_str(), &service_hkey) != ERROR_SUCCESS)
    {
        LOG("[-] RegCreateKey error %d", GetLastError());

        return false;
    }

    if (RegSetKeyValue(service_hkey, nullptr, L"ImagePath", REG_EXPAND_SZ, nt_path.c_str(), sizeof(wchar_t) * nt_path.size()) != ERROR_SUCCESS)
    {
        LOG("[-] RegSetKeyValue error %d", GetLastError());

        RegCloseKey(service_hkey);
        
        return false;
    }

    if (RegSetKeyValue(service_hkey, nullptr, L"Type", REG_DWORD, &service_type_kernel, sizeof(DWORD)) != ERROR_SUCCESS)
    {
        LOG("[-] RegSetKeyValue error %d", GetLastError());

        RegCloseKey(service_hkey);

        return false;
    }

    RegCloseKey(service_hkey);

    HMODULE nt_dll = GetModuleHandle(L"ntdll.dll");

    if (!nt_dll)
    {
        LOG("[-] GetModuleHandle error %d", GetLastError());

        return false;
    }

    NTSTATUS nt_status;

    auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(nt_dll, "RtlAdjustPrivilege");
    auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(nt_dll, "NtLoadDriver");

    BOOLEAN SeLoadDriverPrivilege_was_enabled;
    nt_status = RtlAdjustPrivilege(nt::Privilege::SeLoadDriverPrivilege, TRUE, FALSE, &SeLoadDriverPrivilege_was_enabled);
    if (!NT_SUCCESS(nt_status))
    {
        LOG("[-] RtlAdjustPrivilege error 0x%X, run file as administrator!", nt_status);

        return false;
    }

    std::wstring driver_service_name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\capcom";
    
    UNICODE_STRING driver_service_name_us;
    RtlInitUnicodeString(&driver_service_name_us, driver_service_name.c_str());

    nt_status = NtLoadDriver(&driver_service_name_us);
    if (!NT_SUCCESS(nt_status))
    {
        if (nt_status != STATUS_IMAGE_ALREADY_LOADED)
        {
            LOG("[-] NtLoadDriver error 0x%X", nt_status);

            return false;
        }
        
        LOG("[>] capcom.sys already loaded.");
    }

    return true;
}

bool service::UnregisterAndStop(const std::wstring& driver_name)
{
    HMODULE nt_dll = GetModuleHandle(L"ntdll.dll");

    if (!nt_dll)
    {
        LOG("[-] GetModuleHandle error %d", GetLastError());

        return false;
    }

    std::wstring service_path = L"SYSTEM\\CurrentControlSet\\Services\\capcom";
    HKEY service_hkey;
    LSTATUS l_status = RegOpenKey(HKEY_LOCAL_MACHINE, service_path.c_str(), &service_hkey);

    if (l_status != ERROR_SUCCESS)
    {
        if (l_status == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        
        LOG("[-] RegOpenKey error %d", GetLastError());

        return false;
    }

    RegCloseKey(service_hkey);

    NTSTATUS nt_status;

    std::wstring driver_service_name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\capcom";

    UNICODE_STRING driver_service_name_us;
    RtlInitUnicodeString(&driver_service_name_us, driver_service_name.c_str());

    auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(nt_dll, "NtUnloadDriver");

    nt_status = NtUnloadDriver(&driver_service_name_us);
    if (!NT_SUCCESS(nt_status))
    {
        LOG("[-] NtUnloadDriver error 0x%X", nt_status);

        return false;
    }

    if (RegDeleteKey(HKEY_LOCAL_MACHINE, service_path.c_str()) != ERROR_SUCCESS)
    {
        LOG("[-] RegDeleteKey error %d", GetLastError());

        return false;
    }

    return true;
}