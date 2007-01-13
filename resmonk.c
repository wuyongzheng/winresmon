#include <ntddk.h> 
#include "resmonk.h"

static int enabled = 0;

DRIVER_OBJECT *driver_object;

static struct event_buffer *event_buffer = NULL;
static HANDLE event_buffer_section = NULL;
static FAST_MUTEX event_buffer_mutex;
static KEVENT *event_buffer_readyevent = NULL;
static HANDLE event_buffer_readyeventhandle = NULL;

void event_buffer_add (struct event *event)
{
	DbgPrint("adding...\n");
	ExAcquireFastMutex(&event_buffer_mutex);
	if (event_buffer->counters[event_buffer->active] < EVENT_BUFFER_SIZE) {
		RtlCopyMemory(&event_buffer->buffers[event_buffer->active][event_buffer->counters[event_buffer->active]], event, sizeof(struct event));
		event_buffer->counters[event_buffer->active] ++;
	} else {
		event_buffer->missing ++;
	}
	if (event_buffer->counters[event_buffer->active] >= EVENT_BUFFER_THRESHOLD && !KeReadStateEvent(event_buffer_readyevent))
		KeSetEvent(event_buffer_readyevent, 0, FALSE);
	ExReleaseFastMutex(&event_buffer_mutex);
	DbgPrint("added.\n");
}

static NTSTATUS event_buffer_init (void)
{
	UNICODE_STRING device_name;
	OBJECT_ATTRIBUTES object_attr;
	LARGE_INTEGER sec_size;
	void *section_object;
	SIZE_T size_not_used = sizeof(struct event_buffer);
	NTSTATUS status;

	/* create shared section object */
	RtlInitUnicodeString(&device_name, L"\\BaseNamedObjects\\resmoneb");
	sec_size.QuadPart = sizeof(struct event_buffer);
	InitializeObjectAttributes(&object_attr, &device_name, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateSection(&event_buffer_section,
			SECTION_ALL_ACCESS,
			&object_attr,
			&sec_size,
			PAGE_READWRITE,
			0x8000000,
			NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ZwCreateSection failed. err=%x\n", status);
		return status;
	}

	/* map section into system address space */
	status = ObReferenceObjectByHandle(event_buffer_section,
			SECTION_ALL_ACCESS,
			NULL,
			KernelMode,
			&section_object,
			NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ObReferenceObjectByHandle failed. err=%x\n", status);
		ZwClose(event_buffer_section);
		event_buffer_section = NULL;
		return status;
	}
	status = MmMapViewInSystemSpace(section_object, &event_buffer, &size_not_used);
	ObDereferenceObject(section_object);
	section_object = NULL;
	if (status != STATUS_SUCCESS) {
		DbgPrint("MmMapViewInSystemSpace failed. err=%x\n", status);
		ZwClose(event_buffer_section);
		event_buffer_section = NULL;
		return status;
	}
	DbgPrint("event_buffer mapped at %x\n", (unsigned int)event_buffer);

	/* create ready event */
	RtlInitUnicodeString(&device_name, L"\\BaseNamedObjects\\resmonready");
	event_buffer_readyevent = IoCreateNotificationEvent(&device_name, &event_buffer_readyeventhandle);
	if (event_buffer_readyevent == NULL) {
		DbgPrint("IoCreateNotificationEvent failed.\n");
		MmUnmapViewInSystemSpace(event_buffer);
		event_buffer = NULL;
		ZwClose(event_buffer_section);
		event_buffer_section = NULL;
		return STATUS_UNSUCCESSFUL;
	}
	KeClearEvent(event_buffer_readyevent);

	/* do some final init */
	ExInitializeFastMutex(&event_buffer_mutex);
	event_buffer->active = 0;
	event_buffer->missing = 0;
	event_buffer->counters[0] = 0;
	event_buffer->counters[1] = 0;

	return STATUS_SUCCESS;
}

static void event_buffer_fini (void)
{
	ZwClose(event_buffer_readyeventhandle);
	event_buffer_readyeventhandle = NULL;
	event_buffer_readyevent = NULL;
	MmUnmapViewInSystemSpace(event_buffer);
	event_buffer = NULL;
	ZwClose(event_buffer_section);
	event_buffer_section = NULL;
}

static NTSTATUS enable (void)
{
	NTSTATUS retval;

	if (enabled) {
		DbgPrint("Opps! calling enable() while enabled\n");
		return STATUS_UNSUCCESSFUL;
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
	retval = syscall_init();
	if (retval != STATUS_SUCCESS)
		goto out4;

	enabled = 1;
	return STATUS_SUCCESS;

out4:
	proc_fini();
out3:
	reg_fini();
out2:
	file_fini();
out1:
	event_buffer_fini();
out0:
	return retval;
}

static void disable (void)
{
	if (!enabled) {
		DbgPrint("Opps! calling disable() while !enabled\n");
		return;
	}

	syscall_fini();
	proc_fini();
	reg_fini();
	file_fini();
	event_buffer_fini();

	enabled = 0;
}

static NTSTATUS dispatch_create (PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	DbgPrint("resmon: IRP_MJ_CREATE\n");
	if (enabled) {
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
	if (!enabled) {
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

	if (!enabled) {
		DbgPrint("opps! calling dispatch_ioctl when !enabled?\n");
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
		ExAcquireFastMutex(&event_buffer_mutex);
		event_buffer->active = !event_buffer->active;
		event_buffer->counters[event_buffer->active] = 0;
		KeClearEvent(event_buffer_readyevent);
		ExReleaseFastMutex(&event_buffer_mutex);

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

static void DriverUnload (PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING str;

	if (enabled)
		disable();

	RtlInitUnicodeString(&str, L"\\DosDevices\\resmon");
	IoDeleteSymbolicLink(&str);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("resmon: Unloaded\n");
}

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
	NTSTATUS status;
	int i;
	UNICODE_STRING device_name, sym_name;

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

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i ++)
		DriverObject->MajorFunction[i] = NULL;
	DriverObject->MajorFunction[IRP_MJ_CREATE] =            dispatch_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] =             dispatch_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =    dispatch_ioctl;
	DriverObject->DriverUnload = DriverUnload;

	DbgPrint("resmon: Loaded\n");
	return STATUS_SUCCESS; 
}
