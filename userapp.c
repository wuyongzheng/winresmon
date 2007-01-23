#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

void process_event (const struct event *event)
{
	switch (event->type) {
	case ET_IGNORE:
		break;
	case ET_FILE_CREATE:
		printf("%u %I64u %5d %5d create: %x \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->status, event->path);
		break;
	case ET_FILE_CLOSE:
		printf("%u %I64u %5d %5d close: \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->path);
		break;
	case ET_FILE_READ:
		printf("%u %I64u %5d %5d read: %x \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->status, event->path);
		break;
	case ET_FILE_WRITE:
		printf("%u %I64u %5d %5d write: %x \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->status, event->path);
		break;
	case ET_FILE_CREATE_MAILSLOT:
		printf("%u %I64u %5d %5d mslot: %x \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->status, event->path);
		break;
	case ET_FILE_CREATE_NAMED_PIPE:
		printf("%u %I64u %5d %5d pipe: %x \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->status, event->path);
		break;
	case ET_PROC_PROC_CREATE:
		printf("%u %I64u %5d %5d proc_create: ppid=%d, pid=%d\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->proc_proc_create.ppid, event->proc_proc_create.pid);
		break;
	case ET_PROC_PROC_TERM:
		printf("%u %I64u %5d %5d proc_term: ppid=%d, pid=%d\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->proc_proc_term.ppid, event->proc_proc_term.pid);
		break;
	case ET_PROC_THREAD_CREATE:
		printf("%u %I64u %5d %5d thread_create: tid=%d\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->proc_thread_create.tid);
		break;
	case ET_PROC_THREAD_TERM:
		printf("%u %I64u %5d %5d thread_term: tid=%d\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->proc_thread_create.tid);
		break;
	case ET_PROC_IMAGE:
		printf("%u %I64u %5d %5d image: %d %08x %d \"%S\"\n",
				event->serial, event->time.QuadPart, event->pid, event->tid,
				event->proc_image.system, event->proc_image.base, event->proc_image.size,
				event->path);
		break;
	default:
		printf("unknown event\n");
	}
}

int main (void)
{
	HANDLE driver_file;
	HANDLE ready_event;
	HANDLE section;
	struct event_buffer *event_buffer;

	driver_file = CreateFile("\\\\.\\resmon",
			GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver_file == INVALID_HANDLE_VALUE) {
		printf("CreateFile(\"\\\\.\\resmon\") failed. err=%d\n", GetLastError());
		return 1;
	}

	ready_event = OpenEvent(SYNCHRONIZE, FALSE, "Global\\resmonready");
	if (ready_event == NULL) {
		printf("OpenEvent(\"Global\\resmonready\") failed. err=%d\n", GetLastError());
		return 1;
	}

	section = OpenFileMapping(FILE_MAP_READ, FALSE, "Global\\resmoneb");
	if (section == NULL) {
		printf("OpenFileMapping(\"Global\\resmoneb\") failed. err=%d\n", GetLastError());
		return 1;
	}

	event_buffer = (struct event_buffer *)MapViewOfFile(section, FILE_MAP_READ, 0, 0, sizeof(struct event_buffer));
	if (event_buffer == NULL) {
		printf("MapViewOfFile() failed. err=%d\n", GetLastError());
		return 1;
	}

	for (;;) {
		DWORD wait_status;
		int event_num;
		struct event *events;
		int i;

		wait_status = WaitForSingleObject(ready_event, INFINITE);
		if (wait_status == WAIT_FAILED) {
			printf("WaitForSingleObject() failed. err=%d\n", GetLastError());
			return 1;
		}
		if (wait_status == WAIT_TIMEOUT || wait_status == WAIT_ABANDONED) {
			printf("WaitForSingleObject() returns %s.\n",
					wait_status == WAIT_TIMEOUT ? "WAIT_TIMEOUT" : "WAIT_ABANDONED");
			return 1;
		}

		if (!DeviceIoControl(driver_file, (ULONG)IOCTL_REQUEST_SWAP,
					NULL, 0, NULL, 0,
					&i, NULL)) {
			printf("DeviceIoControl() failed %d\n", GetLastError());
			return 1;
		}

		event_num = event_buffer->counters[!event_buffer->active];
		events = event_buffer->buffers[!event_buffer->active];
		for (i = 0; i < event_num; i ++) {
			process_event(&events[i]);
		}
	}

	return 0;
}
