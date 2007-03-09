#include <ntddk.h> 
#include "resmonk.h"

static unsigned int event_serial = 0;
static struct event_buffer *event_buffer = NULL;
static HANDLE event_buffer_section = NULL;
static FAST_MUTEX event_buffer_mutex;
static KEVENT *event_buffer_readyevent = NULL;
static HANDLE event_buffer_readyeventhandle = NULL;

struct event *event_buffer_start_add (void)
{
	struct event *event;

	if (daemon_pid == (unsigned long)PsGetCurrentProcessId() || daemon_pid == 0)
		return NULL;

	ExAcquireFastMutex(&event_buffer_mutex);
	event_serial ++;
	if (event_buffer->counters[event_buffer->active] < EVENT_BUFFER_SIZE) {
		event = &event_buffer->buffers[event_buffer->active][event_buffer->counters[event_buffer->active]];
		event_buffer->counters[event_buffer->active] ++;

		event->serial = event_serial;
		KeQuerySystemTime(&event->time);
		event->pid = (unsigned long)PsGetCurrentProcessId();
		event->tid = (unsigned long)PsGetCurrentThreadId();
	} else {
		event = NULL;
		event_buffer->missing ++;
		ExReleaseFastMutex(&event_buffer_mutex);
	}

	return event;
}

void event_buffer_finish_add (void)
{
	ExReleaseFastMutex(&event_buffer_mutex);
	if (event_buffer->counters[event_buffer->active] >= EVENT_BUFFER_THRESHOLD && !KeReadStateEvent(event_buffer_readyevent))
		KeSetEvent(event_buffer_readyevent, 0, FALSE);
}

void event_buffer_cancel_add (void)
{
	event_serial --;
	event_buffer->counters[event_buffer->active] --;
	ExReleaseFastMutex(&event_buffer_mutex);
}

void event_buffer_swap (void)
{
	ExAcquireFastMutex(&event_buffer_mutex);
	event_buffer->active = !event_buffer->active;
	event_buffer->counters[event_buffer->active] = 0;
	KeClearEvent(event_buffer_readyevent);
	ExReleaseFastMutex(&event_buffer_mutex);
}

NTSTATUS event_buffer_init (void)
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
	event_serial = 0;
	ExInitializeFastMutex(&event_buffer_mutex);
	event_buffer->active = 0;
	event_buffer->missing = 0;
	event_buffer->counters[0] = 0;
	event_buffer->counters[1] = 0;

	return STATUS_SUCCESS;
}

void event_buffer_fini (void)
{
	ZwClose(event_buffer_readyeventhandle);
	event_buffer_readyeventhandle = NULL;
	event_buffer_readyevent = NULL;
	MmUnmapViewInSystemSpace(event_buffer);
	event_buffer = NULL;
	ZwClose(event_buffer_section);
	event_buffer_section = NULL;
}

