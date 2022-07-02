# driver_mapper

Uses capcom.sys driver to exploit.
You should have custom entry point and disable security check (/GS-) to load your driver without BSOD.
To set custom entry point go to "Linker" option and replace FxDriverEntry to your own entry function.
You also should create DriverObject using "IoCreateDriver" function because it isn't passes as argument at start.
