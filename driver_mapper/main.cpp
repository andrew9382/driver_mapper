#include "includes.hpp"

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		PRINT_USAGE();

		return 1;
	}

	std::filesystem::path path_to_driver(argv[1]);

	if (path_to_driver.extension() != ".sys")
	{
		PRINT_USAGE();

		return 1;
	}

	if (!capcom.Load())
	{
		LOG("[-] Can't load capcom.sys");

		return 1;
	}

	LOG("[+] capcom.sys loaded!");
	
	if (!driver_mapper::LoadDriver(path_to_driver))
	{
		LOG("[-] Can't load your driver");
	}

	if (!capcom.Unload())
	{
		LOG("[-] Can't unload capcom.sys");

		return 1;
	}

	LOG("[+] capcom.sys unloaded!");

	return 0;
}