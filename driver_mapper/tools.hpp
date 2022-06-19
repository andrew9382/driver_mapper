#pragma once

namespace tools
{
	bool CreateFileFromMemory(const std::wstring file_full_name, const BYTE* buffer, size_t size);
}