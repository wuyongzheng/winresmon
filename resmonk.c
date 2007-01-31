#include <ntddk.h> 
#include "resmonk.h"

unsigned long daemon_pid = 0; // monitor is disabled when daemon not is connected

DRIVER_OBJECT *driver_object;

static NTSTATUS enable (void)
{
	NTSTATUS retval;

	if (daemon_pid) {
		DbgPrint("Opps! calling enable() when daemon_pid = %u\n", daemon_pid);
		return STATUS_UNSUCCESSFUL;
	}

	daemon_pid = (unsigned long)PsGetCurrentProcessId();
	if (daemon_pid == 0) {
		DbgPrint("Opps! PsGetCurrentProcessId() = 0\n");
		retval = STATUS_UNSUCCESSFUL;
		goto out0;
	}

	retval = event_buffer_init();
	if (retval != STATUS_SUCCESS)
		goto out0;
	retval = file_init();
	if (retval != STATUS_SUCCESS)
		goto out1;
	retval = reg_init();
	if (retval != STATUS_SUCCESS)
		goto out2;
	retval = proc_init();
	if (retval != STATUS_SUCCESS)
		goto out3;

	return STATUS_SUCCESS;

out3:
	reg_fini();
out2:
	file_fini();
out1:
	event_buffer_fini();
out0:
	daemon_pid = 0;
	return retval;
}

static void disable (void)
{
	if (!daemon_pid) {
		DbgPrint("Opps! calling disable() while daemon_pid = 0\n");
		return;
	}

	proc_fini();
	reg_fini();
	file_fini();
	event_buffer_fini();

	daemon_pid = 0;
}

static NTSTATUS dispatch_create (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	DbgPrint("resmon: IRP_MJ_CREATE\n");
	if (daemon_pid) {
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_UNSUCCESSFUL;
	} else {
		NTSTATUS retval = enable();
		if (retval != STATUS_SUCCESS) {
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = retval;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return retval;
		} else {
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}
	}
}

static NTSTATUS dispatch_close (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	DbgPrint("resmon: IRP_MJ_CLOSE\n");
	if (!daemon_pid) {
		DbgPrint("opps! close without open?\n");
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	} else {
		disable();
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
		DbgPrint("opps! calling dispatch_ioctl when daemon_pid = 0?\n");
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
		disable();

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
		DbgPrint("IoCreateDevice failed\n");
		return status;
	}

	RtlInitUnicodeString(&sym_name, L"\\DosDevices\\resmon");
	status = IoCreateSymbolicLink(&sym_name, &device_name);
	if(status != STATUS_SUCCESS) {
		DbgPrint("IoCreateSymbolicLink failed\n");
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i ++)
		DriverObject->MajorFunction[i] = dispatch_invalid;
	DriverObject->MajorFunction[IRP_MJ_CREATE] =            dispatch_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] =             dispatch_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =    dispatch_ioctl;
	DriverObject->DriverUnload = DriverUnload;

	DbgPrint("resmon: Loaded\n");
	return STATUS_SUCCESS; 
}
