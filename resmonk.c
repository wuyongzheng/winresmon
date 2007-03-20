#include <ntddk.h> 
#include "resmonk.h"

unsigned long daemon_pid = 0; // monitor is disabled when daemon not is connected
static int starting = 0;

DRIVER_OBJECT *driver_object;

static NTSTATUS resmonk_start (void)
{
	NTSTATUS retval;

	ASSERT(!daemon_pid);

	// there can be race condition, but ....
	if (starting) {
		return STATUS_UNSUCCESSFUL;
	}
	starting = 1;

	retval = handle_table_start();
	if (retval != STATUS_SUCCESS)
		goto out1;
	retval = event_buffer_start();
	if (retval != STATUS_SUCCESS)
		goto out2;
	retval = file_start();
	if (retval != STATUS_SUCCESS)
		goto out3;
	retval = reg_start();
	if (retval != STATUS_SUCCESS)
		goto out4;
	retval = proc_start();
	if (retval != STATUS_SUCCESS)
		goto out5;

	daemon_pid = (unsigned long)PsGetCurrentProcessId();
	ASSERT(daemon_pid != 0);

	starting = 0;
	return STATUS_SUCCESS;

out5:
	reg_stop();
out4:
	file_stop();
out3:
	event_buffer_stop();
out2:
	handle_table_stop();
out1:
	starting = 0;
	return retval;
}

static void resmonk_stop (void)
{
	ASSERT(daemon_pid);
	daemon_pid = 0;

	starting = 1;
	proc_stop();
	reg_stop();
	file_stop();
	event_buffer_stop();
	handle_table_stop();
	starting = 0;
}

static NTSTATUS dispatch_create (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	if (daemon_pid) {
		DbgPrint("resmon: start failed. (already started)\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_UNSUCCESSFUL;
	} else {
		NTSTATUS retval = resmonk_start();
		if (retval != STATUS_SUCCESS) {
			DbgPrint("resmon: start failed.\n");
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = retval;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return retval;
		} else {
			DbgPrint("resmon: started.\n");
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}
	}
}

static NTSTATUS dispatch_close (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	if (!daemon_pid) {
		DbgPrint("resmon: opps! close without open?\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	} else {
		resmonk_stop();
		DbgPrint("resmon: stopped.\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
}

static NTSTATUS dispatch_ioctl (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	PIO_STACK_LOCATION irp_stack;

	if (!daemon_pid) {
		DbgPrint("resmon: opps! calling dispatch_ioctl when daemon_pid = 0?\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	irp_stack = IoGetCurrentIrpStackLocation(irp);

	switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_REQUEST_TEST:
		if (irp_stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(int) ||
				irp_stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(int)) {
			DbgPrint("resmon: InputBufferLength or OutputBufferLength is not 4\n");
			irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_BUFFER_TOO_SMALL;
		}
		(*(int *)(irp->AssociatedIrp.SystemBuffer)) ++;
		irp->IoStatus.Information = sizeof(int);
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	case IOCTL_REQUEST_SWAP:
		event_buffer_swap();
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	default:
		DbgPrint("resmon: unknown IOCTL\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
}

static NTSTATUS dispatch_invalid (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_INVALID_DEVICE_REQUEST;
}

static void DriverUnload (PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING str;

	if (daemon_pid)
		resmonk_stop();

	handle_table_fini();
	event_buffer_fini();
	RtlInitUnicodeString(&str, L"\\DosDevices\\resmon");
	IoDeleteSymbolicLink(&str);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("resmon: Unloaded\n");
}

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
	NTSTATUS status;
	UNICODE_STRING device_name, sym_name;
	int i;

	driver_object = DriverObject;

	RtlInitUnicodeString(&device_name, L"\\Device\\resmon");
	status = IoCreateDevice(
			DriverObject,
			0,
			&device_name,
			FILE_DEVICE_RESMON,
			0,
			TRUE,
			&DriverObject->DeviceObject);
	if(status != STATUS_SUCCESS) {
		DbgPrint("resmon: IoCreateDevice failed\n");
		return status;
	}

	RtlInitUnicodeString(&sym_name, L"\\DosDevices\\resmon");
	status = IoCreateSymbolicLink(&sym_name, &device_name);
	if(status != STATUS_SUCCESS) {
		DbgPrint("resmon: IoCreateSymbolicLink failed\n");
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i ++)
		DriverObject->MajorFunction[i] = dispatch_invalid;
	DriverObject->MajorFunction[IRP_MJ_CREATE] =            dispatch_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] =             dispatch_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =    dispatch_ioctl;
	DriverObject->DriverUnload = DriverUnload;

	status = event_buffer_init();
	if (status != STATUS_SUCCESS) {
		IoDeleteSymbolicLink(&sym_name);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}
	status = handle_table_init();
	if (status != STATUS_SUCCESS) {
		event_buffer_fini();
		IoDeleteSymbolicLink(&sym_name);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	DbgPrint("resmon: Loaded\n");
	return STATUS_SUCCESS; 
}
