#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation         = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4
	FileStandardInformation,        // 5
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileNormalizedNameInformation,           // 48
	FileNetworkPhysicalNameInformation,      // 49
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

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
	case ET_FILE_QUERY_INFORMATION:
		switch (event->file_info.info_type) {
		case FileAllInformation: // TODO
			printf("queryinfo: t=FileAllInformation s=%d \"%S\"\n",
					event->file_info.info_size,
					event->path);
			break;
		case FileAttributeTagInformation:
			printf("queryinfo: t=FileAttributeTagInformation attr=0x%x tag=0x%x \"%S\"\n",
					event->file_info.info_data.file_info_attribute_tag.file_attributes,
					event->file_info.info_data.file_info_attribute_tag.reparse_tag,
					event->path);
			break;
		case FileBasicInformation:
			printf("queryinfo: t=FileBasicInformation ct=%I64u lat=%I64u lwt=%I64u lct=%I64u attr=0x%x \"%S\"\n",
					event->file_info.info_data.file_info_basic.creation_time,
					event->file_info.info_data.file_info_basic.last_access_time,
					event->file_info.info_data.file_info_basic.last_write_time,
					event->file_info.info_data.file_info_basic.change_time,
					event->file_info.info_data.file_info_basic.file_attributes,
					event->path);
			break;
		case FileCompressionInformation:
			printf("queryinfo: t=FileCompressionInformation size=%I64u format=%d unit=%d chunk=%d cluster=%d reserved=%d,%d,%d \"%S\"\n",
					event->file_info.info_data.file_info_compression.compressed_file_size,
					event->file_info.info_data.file_info_compression.compression_format,
					event->file_info.info_data.file_info_compression.compression_unit_shift,
					event->file_info.info_data.file_info_compression.chunk_shift,
					event->file_info.info_data.file_info_compression.cluster_shift,
					event->file_info.info_data.file_info_compression.reserved[0],
					event->file_info.info_data.file_info_compression.reserved[1],
					event->file_info.info_data.file_info_compression.reserved[2],
					event->path);
			break;
		case FileEaInformation:
			printf("queryinfo: t=FileEaInformation size=%d \"%S\"\n",
					event->file_info.info_data.file_info_ea.ea_size,
					event->path);
			break;
		case FileInternalInformation:
			printf("queryinfo: t=FileInternalInformation index=%I64u \"%S\"\n",
					event->file_info.info_data.file_info_internal.index_number,
					event->path);
			break;
		case FileNameInformation:
			printf("queryinfo: t=FileNameInformation name=\"%S\" \"%S\"\n",
					event->file_info.info_data.file_info_name.file_name,
					event->path);
			break;
		case FileNetworkOpenInformation:
			printf("queryinfo: t=FileNetworkOpenInformation ct=%I64u lat=%I64u lwt=%I64u lct=%I64u as=%I64u eof=%I64u attr=0x%x \"%S\"\n",
					event->file_info.info_data.file_info_network_open.creation_time,
					event->file_info.info_data.file_info_network_open.last_access_time,
					event->file_info.info_data.file_info_network_open.last_write_time,
					event->file_info.info_data.file_info_network_open.change_time,
					event->file_info.info_data.file_info_network_open.allocation_size,
					event->file_info.info_data.file_info_network_open.end_of_file,
					event->file_info.info_data.file_info_network_open.file_attributes,
					event->path);
			break;
		case FilePositionInformation:
			printf("queryinfo: t=FilePositionInformation pos=%I64u \"%S\"\n",
					event->file_info.info_data.file_info_position.current_byte_offset,
					event->path);
			break;
		case FileStandardInformation:
			printf("queryinfo: t=FileStandardInformation as=%I64u eof=%I64u links=%d delete=%s dir=%s \"%S\"\n",
					event->file_info.info_data.file_info_standard.allocation_size,
					event->file_info.info_data.file_info_standard.end_of_file,
					event->file_info.info_data.file_info_standard.number_of_links,
					event->file_info.info_data.file_info_standard.delete_pending ? "true" : "false",
					event->file_info.info_data.file_info_standard.directory ? "true" : "false",
					event->path);
			break;
		case FileStreamInformation:
			printf("queryinfo: t=FileStreamInformation next=%lu size=%I64u as=%I64u name=\"%S\" \"%S\"\n",
					event->file_info.info_data.file_info_stream.next_entry_offset,
					event->file_info.info_data.file_info_stream.stream_size,
					event->file_info.info_data.file_info_stream.stream_allocation_size,
					event->file_info.info_data.file_info_stream.stream_name,
					event->path);
			break;
		default:
			printf("queryinfo: t=%d s=%d \"%S\"\n",
					event->file_info.info_type, event->file_info.info_size, event->path);
		}
		break;
	case ET_FILE_SET_INFORMATION:
		switch (event->file_info.info_type) {
		case FileAllocationInformation:
			printf("setinfo: t=FileAllocationInformation AllocationSize=%I64u \"%S\"\n",
					event->file_info.info_data.file_info_allocation.allocation_size,
					event->path);
			break;
		case FileBasicInformation:
			printf("setinfo: t=FileBasicInformation ct=%I64u lat=%I64u lwt=%I64u lct=%I64u attr=0x%x \"%S\"\n",
					event->file_info.info_data.file_info_basic.creation_time,
					event->file_info.info_data.file_info_basic.last_access_time,
					event->file_info.info_data.file_info_basic.last_write_time,
					event->file_info.info_data.file_info_basic.change_time,
					event->file_info.info_data.file_info_basic.file_attributes,
					event->path);
			break;
		case FileDispositionInformation:
			printf("setinfo: t=FileDispositionInformation delete=%s \"%S\"\n",
					event->file_info.info_data.file_info_disposition.delete_file ? "true" : "false",
					event->path);
			break;
		case FileEndOfFileInformation:
			printf("setinfo: t=FileEndOfFileInformation end=%I64u \"%S\"\n",
					event->file_info.info_data.file_info_end_of_file.end_of_file,
					event->path);
			break;
		case FileLinkInformation:
			printf("setinfo: t=FileLinkInformation replace=%s root=0x%x name=\"%S\" \"%S\"\n",
					event->file_info.info_data.file_info_link.replace_if_exists ? "true" : "false",
					event->file_info.info_data.file_info_link.root_directory,
					event->file_info.info_data.file_info_link.file_name,
					event->path);
			break;
		case FilePositionInformation:
			printf("setinfo: t=FilePositionInformation pos=%I64u \"%S\"\n",
					event->file_info.info_data.file_info_position.current_byte_offset,
					event->path);
			break;
		case FileRenameInformation:
			printf("setinfo: t=FileRenameInformation replace=%s root=%x name=\"%S\" \"%S\"\n",
					event->file_info.info_data.file_info_rename.replace_if_exists ? "true" : "false",
					event->file_info.info_data.file_info_rename.root_directory,
					event->file_info.info_data.file_info_rename.file_name,
					event->path);
			break;
		case FileValidDataLengthInformation:
			printf("setinfo: t=FileValidDataLengthInformation len=%I64u \"%S\"\n",
					event->file_info.info_data.file_info_valid_data_length.valid_data_length,
					event->path);
			break;
		default:
			printf("setinfo: t=%d s=%d \"%S\"\n",
					event->file_info.info_type, event->file_info.info_size, event->path);
		}
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
