#include "includes.hpp"

bool tools::CreateFileFromMemory(const std::wstring file_full_name, const BYTE* buffer, size_t size)
{
    if (file_full_name.empty() || !buffer || !size)
    {
        return false;
    }

    if (std::filesystem::exists(file_full_name))
    {
        try
        {
            std::filesystem::remove(file_full_name);
        }
        catch (std::exception& ex)
        {
            LOG("%s", ex.what());
        }
    }

    std::fstream file(file_full_name, std::ios::binary | std::ios::out);
    
    file.write((char*)buffer, size);
    file.close();

    return true;
}
