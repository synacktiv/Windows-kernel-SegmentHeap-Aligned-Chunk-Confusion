#pragma once

#include <ntddk.h>

#define TAG_SYN 0x414e5953

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH IrpNotImplementedHandler;
NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
