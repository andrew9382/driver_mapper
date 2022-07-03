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

bool tools::MapFileToMemory(std::filesystem::path& path_to_file, BYTE** out_buffer, size_t* out_size)
{
    if (path_to_file.empty() || !out_buffer || !out_size)
    {
        return false;
    }

    std::fstream file(path_to_file, std::ios::in | std::ios::binary);
   
    if (!file.good())
    {
        return false;
    }

    size_t size_of_file = std::filesystem::file_size(path_to_file);

    if (!size_of_file || size_of_file < PAGE_SIZE)
    {
        file.close();

        return false;
    }

    BYTE* file_raw = new BYTE[size_of_file];
    
    if (!file_raw)
    {
        file.close();

        return false;
    }

    file.read((char*)file_raw, size_of_file);
    file.close();

    *out_size = size_of_file;
    *out_buffer = file_raw;

    return true;
}
