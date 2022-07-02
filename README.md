# driver_mapper

uses capcom.sys driver to exploit.
you should have custom entry point and disable security check (/GS-) to load your driver without BSOD.
to set custom entry point go to "Linker" option and replace FxDriverEntry to your own entry function.
you also should create DriverObject using "IoCreateDriver" function because it isn't passes as argument at start.
