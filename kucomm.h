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

#define MAX_PATH_SIZE 256 // number of unicode characters
#define MAX_IO_SIZE 64    // number of bytes

#define EVENT_BUFFER_SIZE 1024
#define EVENT_BUFFER_THRESHOLD (EVENT_BUFFER_SIZE / 2)

enum event_type {
	ET_IGNORE,
	ET_FILE_CREATE,
	ET_FILE_CLOSE,
	ET_FILE_READ,
	ET_FILE_WRITE,
	ET_FILE_CREATE_MAILSLOT,
	ET_FILE_CREATE_NAMED_PIPE,
	ET_FILE_QUERY_INFORMATION,
	ET_FILE_SET_INFORMATION,
	ET_REG_CLOSE,
	ET_REG_CREATE,
	ET_REG_DELETE,
	ET_REG_DELETEVALUE,
	ET_REG_ENUMERATE,
	ET_REG_ENUMERATEVALUE,
	ET_REG_FLUSH,
	ET_REG_OPEN,
	ET_REG_QUERY,
	ET_REG_QUERYVALUE,
	ET_REG_SETVALUE,
	ET_PROC_PROC_CREATE,
	ET_PROC_PROC_TERM,
	ET_PROC_THREAD_CREATE,
	ET_PROC_THREAD_TERM,
	ET_PROC_IMAGE,
	NUMBER_OF_ET
};

struct event {
	LARGE_INTEGER time; // from KeQuerySystemTime
	unsigned int serial;
	unsigned long pid;
	unsigned long tid;
	enum event_type type;
	unsigned long status;
	int path_length; // <= MAX_PATH_SIZE - 1
	short path[MAX_PATH_SIZE]; // always '\0' terminated
	union {
		struct {
			ACCESS_MASK desired_access; // e.g. FILE_READ_EA
			unsigned long share_mode; // e.g. FILE_SHARE_READ
			unsigned long attributes; // e.g. FILE_ATTRIBUTE_HIDDEN
			unsigned long creation_disposition; // e.g. FILE_OPEN_IF
			unsigned long create_options; // e.g. FILE_DIRECTORY_FILE
		} file_create;
		struct {
			LARGE_INTEGER offset;
			unsigned long length;
			char data[MAX_IO_SIZE];
		} file_rw;
		struct {
			int info_type;
			int info_size;
			union {
				struct {
					LARGE_INTEGER allocation_size;
				} file_info_allocation;
				struct {
					unsigned long file_attributes;
					unsigned long reparse_tag;
				} file_info_attribute_tag;
				struct {
					LARGE_INTEGER creation_time;
					LARGE_INTEGER last_access_time;
					LARGE_INTEGER last_write_time;
					LARGE_INTEGER change_time;
					unsigned long file_attributes;
				} file_info_basic;
				struct {
					LARGE_INTEGER compressed_file_size;
					unsigned short compression_format;
					unsigned char compression_unit_shift;
					unsigned char chunk_shift;
					unsigned char cluster_shift;
					unsigned char reserved[3];
				} file_info_compression;
				struct {
					int delete_file;
				} file_info_disposition;
				struct {
					unsigned long ea_size;
				} file_info_ea;
				struct {
					LARGE_INTEGER end_of_file;
				} file_info_end_of_file;
				struct {
					LARGE_INTEGER index_number;
				} file_info_internal;
				struct {
					int replace_if_exists;
					HANDLE root_directory;
					unsigned long file_name_length;
					short file_name[MAX_PATH_SIZE];
				} file_info_link;
				struct {
					unsigned long file_name_length;
					short file_name[MAX_PATH_SIZE];
				} file_info_name;
				struct {
					LARGE_INTEGER creation_time;
					LARGE_INTEGER last_access_time;
					LARGE_INTEGER last_write_time;
					LARGE_INTEGER change_time;
					LARGE_INTEGER allocation_size;
					LARGE_INTEGER end_of_file;
					unsigned long file_attributes;
				} file_info_network_open;
				struct {
					LARGE_INTEGER current_byte_offset;
				} file_info_position;
				struct {
					int replace_if_exists;
					HANDLE root_directory;
					unsigned long file_name_length;
					short file_name[MAX_PATH_SIZE];
				} file_info_rename;
				struct {
					LARGE_INTEGER allocation_size;
					LARGE_INTEGER end_of_file;
					unsigned long number_of_links;
					int delete_pending;
					int directory;
				} file_info_standard;
				struct {
					unsigned long next_entry_offset;
					unsigned long stream_name_length;
					LARGE_INTEGER stream_size;
					LARGE_INTEGER stream_allocation_size;
					short stream_name[MAX_PATH_SIZE];
				} file_info_stream;
				struct {
					LARGE_INTEGER valid_data_length;
				} file_info_valid_data_length;
			} info_data;
		} file_info;
		struct {
			HANDLE handle;
		} reg_close;
		struct {
			HANDLE handle;
			ACCESS_MASK desired_access; // e.g. KEY_QUERY_VALUE
			unsigned long create_options; // e.g. REG_OPTION_VOLATILE
			unsigned long creation_disposition; // e.g. e.g. REG_CREATED_NEW_KEY
		} reg_create;
		struct {
			HANDLE handle;
		} reg_delete;
		struct {
			HANDLE handle;
		} reg_delete_value;
		struct {
			HANDLE handle;
			ACCESS_MASK desired_access;
		} reg_open;
		struct {
			HANDLE handle;
			unsigned long value_type;
			unsigned long value_length;
			char value[MAX_IO_SIZE];
		} reg_rw;
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
};

struct event_buffer {
	int active; /* active is the one which keeps adding */
	unsigned int missing;
	unsigned int counters[2];
	struct event buffers[2][EVENT_BUFFER_SIZE];
};

#endif
