
#include <ntddk.h>
#include "Driver.h"
#include "Ioctl.h"

#define MAX_SPRAY 0x1000
#define MAX_ALLOCS_BY_SPRAY 0x10000

char * g_Buffer  = nullptr;

size_t nb_sprays = 0;
spray_t * g_sprays[MAX_SPRAY] = { NULL };


extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UINT32 i = 0;
	UNICODE_STRING DeviceName, DosDeviceName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&DeviceName, L"\\Device\\vulnerable_driver");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\vulnerable_driver");

	// Create the device
	Status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(Status)) {
		if (DeviceObject) {
			// Delete the device
			IoDeleteDevice(DeviceObject);
		}
		return Status;
	}

	// Assign the IRP handlers
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
	}

	// Assign the IRP handlers for Create, Close and Device Control
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

	// Assign the driver Unload routine
	DriverObject->DriverUnload = DriverUnload;


	// Set the flags
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	// Create the symbolic link
	Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	return Status;
}

NTSTATUS CommandArbitraryRead(ioctl_arb_primitive_t * user_input, char * user_output, ULONG * OutputBytes)
{
	size_t read_size = user_input->size;

	memcpy(user_output, (void*)user_input->where, read_size);
	*OutputBytes = (ULONG)read_size;
	return STATUS_SUCCESS;
}

NTSTATUS CommandArbitraryWrite(ioctl_arb_primitive_t * user_input, size_t * user_output)
{
	memcpy((void*)user_input->where, user_input->what, user_input->size);
	*user_output = user_input->size;
	return STATUS_SUCCESS;
}



NTSTATUS CommandAlloc(ioctl_alloc_t * user_input, uintptr_t * user_output)
{
	g_Buffer = (char *) ExAllocatePoolWithTag(user_input->pooltype, user_input->alloc_size, user_input->tag);
	*user_output = (uintptr_t)g_Buffer;
	return STATUS_SUCCESS;
}

NTSTATUS CommandFree(void)
{
	ExFreePoolWithTag(g_Buffer, TAG_SYN);
	return STATUS_SUCCESS;
}

NTSTATUS CommandCopy(ioctl_copy_t * user_input)
{
	RtlCopyMemory(g_Buffer, user_input->data, user_input->buffer_size);
	return STATUS_SUCCESS;
}

NTSTATUS CommandSpray(ioctl_spray_t * user_input, uintptr_t * user_output, ULONG* OutputBytes)
{
	size_t spray_index = 0;
	bool found = false;

	if (nb_sprays >= MAX_SPRAY)
		return STATUS_INVALID_PARAMETER;

	if (user_input->nb_allocs > MAX_ALLOCS_BY_SPRAY)
		return STATUS_INVALID_PARAMETER;

	for (size_t i = 0; i < MAX_SPRAY; i++)
	{
		if (!g_sprays[i])
		{
			spray_index = i;
			found = true;
			break;
		}
	}

	if (!found)
		return STATUS_INVALID_PARAMETER;


	spray_t * spray = (spray_t *)ExAllocatePoolWithTag(PagedPool, sizeof(spray_t) + (user_input->nb_allocs * sizeof(uintptr_t)), TAG_SYN);


	spray->nb_allocs = user_input->nb_allocs;
	spray->alloc_size = user_input->alloc_size;
	spray->pooltype = user_input->pooltype;
	spray->tag = user_input->tag;
	spray->spray_index = spray_index;

	for (size_t i = 0; i < spray->nb_allocs; i++)
	{
		spray->allocs[i] = ExAllocatePoolWithTag(spray->pooltype, spray->alloc_size, spray->tag);
		memset(spray->allocs[i], 0x42, spray->alloc_size);
	}

	g_sprays[spray_index] = spray;
	nb_sprays++;

	*user_output = spray->spray_index;
	memcpy(((char *)user_output) + sizeof(size_t), (void*)spray->allocs, spray->nb_allocs * sizeof(uintptr_t));
	*OutputBytes = (ULONG)(sizeof(size_t) + (spray->nb_allocs * sizeof(uintptr_t)));

	return STATUS_SUCCESS;
}

NTSTATUS CommandUnspray(size_t spray_index)
{
	spray_t * spray = NULL;

	if (spray_index >= MAX_SPRAY)
		return STATUS_INVALID_PARAMETER;

	spray = g_sprays[spray_index];

	if (!spray)
		return STATUS_INVALID_PARAMETER;

	for (size_t i = 0; i < spray->nb_allocs; i++)
	{
		if (spray->allocs[i] != 0)
		{
			ExFreePoolWithTag(spray->allocs[i], spray->tag);
			spray->allocs[i] = nullptr;
		}
	}
	ExFreePoolWithTag(spray, TAG_SYN);
	g_sprays[spray_index] = NULL;
	nb_sprays--;
	return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	ULONG IoControlCode = 0;
	PIO_STACK_LOCATION IrpSp = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG OutputBytes = 0;

	UNREFERENCED_PARAMETER(DeviceObject);

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	if (IrpSp) {
		switch (IoControlCode) {

		case IOCTL_ALLOC_BUFFER:
			Status = CommandAlloc((ioctl_alloc_t *)Irp->AssociatedIrp.SystemBuffer, (uintptr_t *)Irp->AssociatedIrp.SystemBuffer);
			OutputBytes = sizeof(uintptr_t);
			break;

		case IOCTL_FREE_BUFFER:
			Status = CommandFree();
			break;

		case IOCTL_COPY:
			Status = CommandCopy((ioctl_copy_t *)Irp->AssociatedIrp.SystemBuffer);
			break;

		case IOCTL_SPRAY:
			Status = CommandSpray((ioctl_spray_t *)Irp->AssociatedIrp.SystemBuffer, (uintptr_t *)Irp->AssociatedIrp.SystemBuffer, &OutputBytes);
			break;

		case IOCTL_UNSPRAY:
			Status = CommandUnspray(*((size_t *)Irp->AssociatedIrp.SystemBuffer));
			break;

		case IOCTL_READ:
			Status = CommandArbitraryRead(((ioctl_arb_primitive_t *)Irp->AssociatedIrp.SystemBuffer), (char *)Irp->AssociatedIrp.SystemBuffer, &OutputBytes);
			break;

		case IOCTL_WRITE:
			Status = CommandArbitraryWrite(((ioctl_arb_primitive_t *)Irp->AssociatedIrp.SystemBuffer), (size_t *)Irp->AssociatedIrp.SystemBuffer);
			OutputBytes = 8;
			break;
		case IOCTL_BP:
			DbgBreakPoint();
			break;

		default:
			Status = STATUS_NOT_SUPPORTED;
			break;
		}
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = OutputBytes;

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING DosDeviceName = { 0 };

	PAGED_CODE();

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\vulnerable_driver");

	// Delete the symbolic link
	IoDeleteSymbolicLink(&DosDeviceName);

	// Delete the device
	IoDeleteDevice(DriverObject->DeviceObject);
}
