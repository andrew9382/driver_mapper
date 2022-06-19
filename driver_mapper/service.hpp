#pragma once

namespace service
{
	bool RegisterAndStart(const std::filesystem::path& path_to_driver);

	bool UnregisterAndStop(const std::wstring& driver_name);
}