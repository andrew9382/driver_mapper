#pragma once

namespace tools
{
	bool CreateFileFromMemory(const std::wstring file_full_name, const BYTE* buffer, size_t size);
	bool MapFileToMemory(std::filesystem::path& path_to_file, BYTE** out_buffer, size_t* out_size);
}