#include "includes.hpp"

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		PRINT_USAGE();

		return 1;
	}

	if (std::filesystem::path(argv[1]).extension() != ".sys")
	{
		PRINT_USAGE();

		return 1;
	}

	if (!capcom.Load())
	{
		LOG("[-] Can't load capcom.sys");

		return 1;
	}
	
	capcom.ExecuteUserFunction(driver_mapper::PrintHelloWorldKernel, (void*)0x8888888888888888);

	if (!capcom.Unload())
	{
		LOG("[-] Can't unload capcom.sys");

		return 1;
	}

	return 0;
}