#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

void process_event (const struct event *event)
{
	switch (event->type) {
	case ET_FILE_CREATE:
		printf("create: %s\n", event->path);
		break;
	case ET_FILE_CLOSE:
		printf("close: %s\n", event->path);
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
