#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

int main (void)
{
	HANDLE driver_file;
	HANDLE ready_event;
	HANDLE section;
	struct event_buffer *event_buffer;
	int recorded = 0;
	unsigned long last_report_tick = 0;
	int last_report_num = 0;

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
					&event_num, NULL)) {
			printf("DeviceIoControl() failed %d\n", GetLastError());
			return 1;
		}

		event_num = event_buffer->reading_count;
		if (event_num <= 0)
			continue;
		if (GetTickCount() >= last_report_tick + 1000 && recorded + event_num > last_report_num) {
			printf("recorded=%8d, last=%8d, missed=%8d\n",
					recorded + event_num,
					event_buffer->pool[event_buffer->reading_tail].serial,
					event_buffer->dropped);
			last_report_tick = GetTickCount();
			last_report_num = recorded + event_num;
		}
		recorded += event_num;
	}

	return 0;
}
