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
#define MAX_STACK_FRAME 32

#define EVENT_BUFFER_SIZE 2048
#define EVENT_BUFFER_FREE_THRESHOLD    (EVENT_BUFFER_SIZE / 2) // triger if free_count < it
#define EVENT_BUFFER_WRITTEN_THRESHOLD (EVENT_BUFFER_SIZE / 4) // triger if written_count > it

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
	ET_TDI_CLEANUP,                        // tdi_general
	ET_TDI_CLOSE,                          // tdi_general
	ET_TDI_CREATE,                         // tdi_create
	ET_TDI_ACCEPT,                         // tdi_accept
	ET_TDI_ACTION,                         // tdi_general
	ET_TDI_ASSOCIATE_ADDRESS,              // tdi_associate_address
	ET_TDI_CONNECT,                        // tdi_connect
	ET_TDI_DISASSOCIATE_ADDRESS,           // tdi_general
	ET_TDI_DISCONNECT,                     // tdi_disconnect
	ET_TDI_LISTEN,                         // tdi_listen
	ET_TDI_QUERY_INFORMATION,              // tdi_query_information
	ET_TDI_RECEIVE,                        // tdi_receive
	ET_TDI_RECEIVE_DATAGRAM,               // tdi_receive_datagram,
	ET_TDI_SEND,                           // tdi_send,
	ET_TDI_SEND_DATAGRAM,                  // tdi_send_datagram,
	ET_TDI_SET_EVENT_HANDLER,              // tdi_set_event_handler,
	ET_TDI_SET_INFORMATION,                // tdi_query_information,
	ET_TDI_EVENT_CONNECT,                  // tdi_event_connect,
	ET_TDI_EVENT_DISCONNECT,               // tdi_event_disconnect,
	ET_TDI_EVENT_ERROR,                    // tdi_event_error,
	ET_TDI_EVENT_RECEIVE,                  // tdi_event_receive,
	ET_TDI_EVENT_RECEIVE_DATAGRAM,         // tdi_event_receive_datagram,
	ET_TDI_EVENT_RECEIVE_EXPEDITED,        // tdi_event_receive,
	ET_TDI_EVENT_SEND_POSSIBLE,            // tdi_event_send_possible,
	ET_TDI_EVENT_CHAINED_RECEIVE,          // tdi_event_chained_receive,
	ET_TDI_EVENT_CHAINED_RECEIVE_DATAGRAM, // tdi_event_chained_receive_datagram,
	ET_TDI_EVENT_CHAINED_RECEIVE_EXPEDITED,// tdi_event_chained_receive,
	ET_TDI_EVENT_ERROR_EX,                 // tdi_event_error_ex
	NUMBER_OF_ET
};

/* only ipv4 currently */
struct tdi_transport_address {
	/* Unix' PF_ and winddk's TDI_ADDRESS_TYPE_ have different numbering.
	 * Let's use winddk's since we are monitoring TDI here.
	 * TDI_ADDRESS_TYPE_IP  = 2
	 * TDI_ADDRESS_TYPE_IP6 = 23
	 * family=0 means unspecified */
	int family;
	union {
		struct {
			unsigned short port; // network/big-endian byte order
			unsigned char addr[4]; // network/big-endian byte order
		} ipv4;
		struct {
			unsigned short port; // network/big-endian byte order
			unsigned char addr[16]; // network/big-endian byte order
		} ipv6;
	};
};

struct event {
	int next;
	LARGE_INTEGER time_pre;
	LARGE_INTEGER time_post;
	unsigned int serial;
	unsigned long pid;
	unsigned long tid;
	enum event_type type;
	unsigned long status;
#ifdef TRACE_STACK
	int stack_n;
	unsigned int stack_ret[MAX_STACK_FRAME];
#endif
	int path_length; // <= MAX_PATH_SIZE - 1
	short path[MAX_PATH_SIZE]; // always '\0' terminated
	union {
		// http://msdn2.microsoft.com/en-us/library/ms795806.aspx
		struct {
			ACCESS_MASK desired_access; // e.g. FILE_READ_EA
			unsigned long share_mode; // e.g. FILE_SHARE_READ
			unsigned long attributes; // e.g. FILE_ATTRIBUTE_HIDDEN
			unsigned long creation_disposition; // e.g. FILE_OPEN_IF
			unsigned long create_options; // e.g. FILE_DIRECTORY_FILE
			unsigned long status_information; // (IoStatusBlock->Information) e.g. FILE_CREATED
		} file_create;
		// http://msdn2.microsoft.com/en-us/library/ms795902.aspx
		struct {
			LARGE_INTEGER offset;
			unsigned long req_length; // buffer size
			unsigned long ret_length; // size read or written
			char data[MAX_IO_SIZE];
		} file_rw;
		// http://msdn2.microsoft.com/en-us/library/ms796040.aspx
		// http://msdn2.microsoft.com/en-us/library/ms795789.aspx
		struct {
			int info_type;
			int info_size;
			union {
				struct {
					// FILE_BASIC_INFORMATION
					LARGE_INTEGER creation_time;
					LARGE_INTEGER last_access_time;
					LARGE_INTEGER last_write_time;
					LARGE_INTEGER change_time;
					unsigned long file_attributes;
					// FILE_STANDARD_INFORMATION
					LARGE_INTEGER allocation_size;
					LARGE_INTEGER end_of_file;
					unsigned long number_of_links;
					int delete_pending;
					int directory;
					// FILE_INTERNAL_INFORMATION
					LARGE_INTEGER index_number;
					// FILE_EA_INFORMATION
					unsigned long ea_size;
					// FILE_ACCESS_INFORMATION
					ACCESS_MASK access_flags;
					// FILE_POSITION_INFORMATION
					LARGE_INTEGER current_byte_offset;
					// FILE_MODE_INFORMATION
					unsigned long mode;
					// FILE_ALIGNMENT_INFORMATION
					unsigned long alignment_requirement;
					// FILE_NAME_INFORMATION
					unsigned long next_entry_offset;
					unsigned long stream_name_length;
					LARGE_INTEGER stream_size;
					LARGE_INTEGER stream_allocation_size;
					short stream_name[MAX_PATH_SIZE];
				} file_info_all;
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
		// http://msdn2.microsoft.com/en-us/library/ms804348.aspx
		struct {
			HANDLE handle;
			ACCESS_MASK desired_access; // e.g. KEY_QUERY_VALUE
			unsigned long create_options; // e.g. REG_OPTION_VOLATILE
			unsigned long creation_disposition; // e.g. e.g. REG_CREATED_NEW_KEY
		} reg_create;
		// http://msdn2.microsoft.com/en-us/library/ms804367.aspx
		struct {
			HANDLE handle;
		} reg_delete;
		// http://msdn2.microsoft.com/en-us/library/ms804372.aspx
		struct {
			HANDLE handle;
		} reg_delete_value;
		// http://msdn2.microsoft.com/en-us/library/ms804360.aspx
		struct {
			HANDLE handle;
			ACCESS_MASK desired_access;
		} reg_open;
		// http://msdn2.microsoft.com/en-us/library/ms804371.aspx
		// http://msdn2.microsoft.com/en-us/library/ms804346.aspx
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
		// http://msdn2.microsoft.com/en-us/library/ms802949.aspx
		struct {
			int system;
			void *base;
			unsigned int size;
		} proc_image;
		struct {
			void *file_object;
		} tdi_general;
		struct {
			void *file_object;
			int type; // 1=control; 2=address; 3=connection
			struct tdi_transport_address addr; // only valid when type=address.
		} tdi_create;
		struct {
			void *file_object;
			struct tdi_transport_address request_addr;
			struct tdi_transport_address return_addr;
		} tdi_accept;
		struct {
			void *file_object;
			void *file_object2;
		} tdi_associate_address;
		struct {
			void *file_object;
			struct tdi_transport_address request_addr;
			struct tdi_transport_address return_addr;
			LARGE_INTEGER timeout;
		} tdi_connect;
		struct {
			void *file_object;
			unsigned long flags;
			struct tdi_transport_address request_addr;
			struct tdi_transport_address return_addr;
			LARGE_INTEGER timeout;
		} tdi_disconnect;
		struct {
			void *file_object;
			unsigned long flags;
			struct tdi_transport_address request_addr;
			struct tdi_transport_address return_addr;
		} tdi_listen;
		struct {
			void *file_object;
			int type;
			struct tdi_transport_address addr;
			union {
				struct {
					unsigned long activity_count;
					struct tdi_transport_address addr;
				} address;
				struct {
					unsigned long status;
					unsigned long event;
					unsigned long transmitted_tsdus;
					unsigned long received_tsdus;
					unsigned long transmission_errors;
					unsigned long receive_errors;
					LARGE_INTEGER throughput;
					LARGE_INTEGER delay;
					unsigned long send_buffer_size;
					unsigned long receive_buffer_size;
					int unreliable; // boolean
				} connection;
			};
		} tdi_query_information;
		struct {
			void *file_object;
			int length;
			unsigned long flags;
			char data[MAX_IO_SIZE];
		} tdi_receive;
		struct {
			void *file_object;
			int length;
			unsigned long flags;
			struct tdi_transport_address request_addr;
			struct tdi_transport_address return_addr;
			char data[MAX_IO_SIZE];
		} tdi_receive_datagram;
		struct {
			void *file_object;
			int length;
			unsigned long flags;
			char data[MAX_IO_SIZE];
		} tdi_send;
		struct {
			void *file_object;
			int length;
			struct tdi_transport_address addr;
			char data[MAX_IO_SIZE];
		} tdi_send_datagram;
		struct {
			void *file_object;
			int type;
			void *handler;
			void *context;
		} tdi_set_event_handler;
		struct {
			void *file_object;
			struct tdi_transport_address addr;
			int user_data_length;
			int options_length;
		} tdi_event_connect;
		struct {
			void *file_object;
			int data_length;
			int information_length;
			unsigned long flags;
		} tdi_event_disconnect;
		struct {
			void *file_object;
			unsigned long cause_status;
		} tdi_event_error;
		struct {
			void *file_object;
			unsigned long flags;
			int bytes_indicated;
			int bytes_available;
			int bytes_taken;
			char data[MAX_IO_SIZE];
		} tdi_event_receive;
		struct {
			void *file_object;
			struct tdi_transport_address addr;
			int options_length;
			unsigned long flags;
			int bytes_indicated;
			int bytes_available;
			int bytes_taken;
			char data[MAX_IO_SIZE];
		} tdi_event_receive_datagram;
		struct {
			void *file_object;
			int bytes_available;
		} tdi_event_send_possible;
		struct {
			void *file_object;
			unsigned long flags;
			int length;
			char data[MAX_IO_SIZE];
		} tdi_event_chained_receive;
		struct {
			void *file_object;
			struct tdi_transport_address addr;
			int options_length;
			unsigned long flags;
			int length;
			char data[MAX_IO_SIZE];
		} tdi_event_chained_receive_datagram;
		struct {
			void *file_object;
			unsigned long cause_status;
			char buffer[MAX_IO_SIZE];
		} tdi_event_error_ex;
	};
};

struct event_buffer {
	int free_head;
	int free_count;
	int reading_head;
	int reading_tail;
	int reading_count;
	int written_head;
	int written_tail;
	int written_count;
	unsigned int serial;
	unsigned int dropped;
	struct event pool [EVENT_BUFFER_SIZE];
};

#endif
