#include <ntddk.h>
#include "resmonk.h"

static void proc_notify_process (HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	struct event *event;

	event = event_buffer_start_add();
	if (event == NULL)
		return;

	if (create) {
		event->type = ET_PROC_PROC_CREATE;
		event->status = 0;
		event->proc_proc_create.ppid = ppid;
		event->proc_proc_create.pid = pid;
		event->path_length = 0;
		event->path[0] = 0;
	} else {
		event->type = ET_PROC_PROC_TERM;
		event->status = 0;
		event->proc_proc_create.ppid = ppid;
		event->proc_proc_create.pid = pid;
		event->path_length = 0;
		event->path[0] = 0;
	}
	event_buffer_finish_add();

	if (!create)
		htable_remove_process_entries((unsigned long)pid);
}

static void proc_notify_thread (HANDLE pid, HANDLE tid, BOOLEAN create)
{
	struct event *event;

	event = event_buffer_start_add();
	if (event == NULL)
		return;

	if (create) {
		event->type = ET_PROC_THREAD_CREATE;
		event->status = 0;
		event->proc_thread_create.tid = tid;
		event->path_length = 0;
		event->path[0] = 0;
	} else {
		event->type = ET_PROC_THREAD_TERM;
		event->status = 0;
		event->proc_thread_term.tid = tid;
		event->path_length = 0;
		event->path[0] = 0;
	}
	event_buffer_finish_add();
}

static void proc_notify_image (PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info)
{
	struct event *event;

	event = event_buffer_start_add();
	if (event == NULL)
		return;

	event->type = ET_PROC_IMAGE;
	event->status = 0;
	event->proc_image.system = info->SystemModeImage;
	event->proc_image.base = info->ImageBase;
	event->proc_image.size = info->ImageSize;
	event->path_length = MAX_PATH_SIZE - 1 < name->Length / 2 ? MAX_PATH_SIZE - 1 : name->Length / 2;
	RtlCopyMemory(event->path, name->Buffer, event->path_length * 2);
	event->path[event->path_length] = 0;
	event_buffer_finish_add();
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
