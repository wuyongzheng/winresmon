#include <ntddk.h>
#include "resmonk.h"

static void proc_notify_process (HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	DbgPrint("resmon: process: %d %d %d\n", ppid, pid, create);
}

static void proc_notify_thread (HANDLE pid, HANDLE tid, BOOLEAN create)
{
	DbgPrint("resmon: thread: %d %d %d\n", pid, tid, create);
}

static void proc_notify_image (PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
	struct event event;
	int path_length;

	DbgPrint("resmon: image: %d %S\n", pid, name == NULL || name->Buffer == NULL ? L"null" : name->Buffer);

	KeQuerySystemTime(&event.time);
	event.pid = PsGetCurrentProcessId();
	event.tid = PsGetCurrentThreadId();
	event.status = 0;
	event.type = ET_PROC_IMAGE;
	event.proc_image.system = info->SystemModeImage;
	event.proc_image.base = info->ImageBase;
	event.proc_image.size = info->ImageSize;
	path_length = MAX_PATH_SIZE - 1 < name->Length / 2 ? MAX_PATH_SIZE - 1 : name->Length / 2;
	RtlCopyMemory(event.path, name->Buffer, path_length * 2);
	event.path[path_length] = 0;
	event_buffer_add(&event);
}

NTSTATUS proc_init (void)
{
	NTSTATUS retval;

	retval = PsSetCreateProcessNotifyRoutine(proc_notify_process, 0);
	if (retval != STATUS_SUCCESS)
		return retval;
	retval = PsSetCreateThreadNotifyRoutine(proc_notify_thread);
	if (retval != STATUS_SUCCESS) {
		PsSetCreateProcessNotifyRoutine(proc_notify_process, 1);
		return retval;
	}
	retval = PsSetLoadImageNotifyRoutine(proc_notify_image);
	if (retval != STATUS_SUCCESS) {
		PsRemoveCreateThreadNotifyRoutine(proc_notify_thread);
		PsSetCreateProcessNotifyRoutine(proc_notify_process, 1);
		return retval;
	}
	return STATUS_SUCCESS;
}

void proc_fini (void)
{
	PsRemoveLoadImageNotifyRoutine(proc_notify_image);
	PsRemoveCreateThreadNotifyRoutine(proc_notify_thread);
	PsSetCreateProcessNotifyRoutine(proc_notify_process, 1);
}
