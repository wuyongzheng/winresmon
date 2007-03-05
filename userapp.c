#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

extern const char *get_ntstatus_name (long status);

void process_event (const struct event *event)
{
	if (event->type == ET_IGNORE)
		return;

	printf("%u %I64u %5d %5d %s ", event->serial, event->time.QuadPart, event->pid, event->tid, get_ntstatus_name(event->status));

	switch (event->type) {
	case ET_FILE_CREATE:
		printf("create: access=%x share=%x attr=%x cd=%x co=%x \"%S\"\n",
				event->file_create.desired_access, event->file_create.share_mode, event->file_create.attributes, event->file_create.creation_disposition, event->file_create.create_options,
				event->path);
		break;
	case ET_FILE_CLOSE:
		printf("close: \"%S\"\n", event->path);
		break;
	case ET_FILE_READ:
		printf("read: %I64u+%lu \"%S\"\n", event->file_rw.offset.QuadPart, event->file_rw.length, event->path);
		break;
	case ET_FILE_WRITE:
		printf("write: %I64u+%lu \"%S\"\n", event->file_rw.offset.QuadPart, event->file_rw.length, event->path);
		break;
	case ET_FILE_CREATE_MAILSLOT:
		printf("mslot: \"%S\"\n", event->path);
		break;
	case ET_FILE_CREATE_NAMED_PIPE:
		printf("pipe: \"%S\"\n", event->path);
		break;
	case ET_REG_CLOSE:
		printf("reg_close: %x \"%S\"\n", event->reg_close.handle, event->path);
		break;
	case ET_REG_CREATE:
		printf("reg_create: hd=%x da=%x co=%x cd=%x \"%S\"\n", event->reg_create.handle, event->reg_create.desired_access, event->reg_create.create_options, event->reg_create.creation_disposition, event->path);
		break;
	case ET_REG_DELETE:
		printf("reg_delete: %x \"%S\"\n", event->reg_delete.handle, event->path);
		break;
	case ET_REG_DELETEVALUE:
		printf("reg_deletevalue: %x \"%S\"\n", event->reg_delete_value.handle, event->path);
		break;
	case ET_REG_OPEN:
		printf("reg_open: %x %x \"%S\"\n", event->reg_open.handle, event->reg_open.desired_access, event->path);
		break;
	case ET_REG_QUERYVALUE:
	case ET_REG_SETVALUE:
		switch (event->reg_rw.value_type) {
		case REG_BINARY:
			printf("reg_%svalue: t=REG_BINARY l=%d \"%S\"\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->reg_rw.value_length, event->path);
			break;
		case REG_DWORD:
			printf("reg_%svalue: t=REG_DWORD v=%x \"%S\"\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					*(unsigned int *)event->reg_rw.value, event->path);
			break;
		case REG_EXPAND_SZ:
			printf("reg_%svalue: t=REG_EXPAND_SZ l=%d v=\"%S\" \"%S\"\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->reg_rw.value_length, event->reg_rw.value, event->path);
			break;
		case REG_SZ:
			printf("reg_%svalue: t=REG_EXPAND_SZ l=%d v=\"%S\" \"%S\"\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->reg_rw.value_length, event->reg_rw.value, event->path);
			break;
		default:
			printf("reg_queryvalue: t=%x l=%d \"%S\"\n", event->reg_rw.value_type, event->reg_rw.value_length, event->path);
		}
		break;
	case ET_PROC_PROC_CREATE:
		printf("proc_create: ppid=%d, pid=%d\n", event->proc_proc_create.ppid, event->proc_proc_create.pid);
		break;
	case ET_PROC_PROC_TERM:
		printf("proc_term: ppid=%d, pid=%d\n", event->proc_proc_term.ppid, event->proc_proc_term.pid);
		break;
	case ET_PROC_THREAD_CREATE:
		printf("thread_create: tid=%d\n", event->proc_thread_create.tid);
		break;
	case ET_PROC_THREAD_TERM:
		printf("thread_term: tid=%d\n", event->proc_thread_create.tid);
		break;
	case ET_PROC_IMAGE:
		printf("image: %d %08x %d \"%S\"\n", event->proc_image.system, event->proc_image.base, event->proc_image.size, event->path);
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

	if(!SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)) {
		printf("SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS) failed. err=%d\n", GetLastError());
	}
	if(!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL)) {
		printf("SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) failed. err=%d\n", GetLastError());
	}

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

		// wait for at most 1 sec
		wait_status = WaitForSingleObject(ready_event, 1000);
		if (wait_status == WAIT_FAILED) {
			printf("WaitForSingleObject() failed. err=%d\n", GetLastError());
			return 1;
		}
		if (wait_status == WAIT_ABANDONED) {
			printf("WaitForSingleObject() returns WAIT_ABANDONED.\n");
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
