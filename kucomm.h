/* Kernel-User communication interface */

#ifndef KUCOMM_H
#define KUCOMM_H

// Microsoft uses 0 - 0x7FFF, OEMs use 0x8000 - 0xFFFF
#define FILE_DEVICE_RESMON  0x00009500

// Microsoft uses function codes 0-0x7FF, OEM's use 0x800 - 0xFFF
#define IOCTL_FUNC_TEST        0x950
#define IOCTL_FUNC_SWAP        0x951

#define IOCTL_REQUEST_TEST \
	CTL_CODE(FILE_DEVICE_RESMON, IOCTL_FUNC_TEST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REQUEST_SWAP \
	CTL_CODE(FILE_DEVICE_RESMON, IOCTL_FUNC_SWAP, METHOD_NEITHER, FILE_ANY_ACCESS)

#define MAX_PATH_SIZE 256

#define EVENT_BUFFER_SIZE 256
#define EVENT_BUFFER_THRESHOLD (EVENT_BUFFER_SIZE*3/4)

enum event_type {
	ET_FILE_CREATE,
	ET_FILE_CLOSE,
	ET_PROC_PROC_CREATE,
	ET_PROC_PROC_TERM,
	ET_PROC_THREAD_CREATE,
	ET_PROC_THREAD_TERM,
	ET_PROC_IMAGE,
	NUMBER_OF_ET
};

struct event {
	unsigned int serial;
	LARGE_INTEGER time; // from KeQuerySystemTime
	HANDLE pid;
	HANDLE tid;
	enum event_type type;
	unsigned long status;
	union {
		struct {
			ACCESS_MASK desired_access; // e.g. FILE_READ_EA
			unsigned long share_mode; // e.g. FILE_SHARE_READ
			unsigned long attributes; // e.g. FILE_ATTRIBUTE_HIDDEN
			unsigned long creation_disposition; // e.g. FILE_OPEN_IF
			unsigned long create_options; // e.g. FILE_DIRECTORY_FILE
		} file_create;
		struct {
			HANDLE ppid;
			HANDLE pid;
		} proc_proc_create;
		struct {
			HANDLE ppid;
			HANDLE pid;
		} proc_proc_term;
		struct {
			HANDLE tid;
		} proc_thread_create;
		struct {
			HANDLE tid;
		} proc_thread_term;
		struct {
			int system;
			void *base;
			unsigned int size;
		} proc_image;
	};
	short path[MAX_PATH_SIZE]; // always '\0' terminated
};

struct event_buffer {
	int active; /* active is the one which keeps adding */
	unsigned int missing;
	unsigned int counters[2];
	struct event buffers[2][EVENT_BUFFER_SIZE];
};

#endif
