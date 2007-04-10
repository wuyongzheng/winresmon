#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

#define FIELD_SEP "\t"

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

	printf("%u" FIELD_SEP "%I64u" FIELD_SEP "%d" FIELD_SEP "%d" FIELD_SEP "%s" FIELD_SEP,
			event->serial,
			event->time.QuadPart,
			event->pid,
			event->tid,
			get_ntstatus_name(event->status));

	switch (event->type) {
	case ET_FILE_CREATE:
		printf("create:" FIELD_SEP "\"%S\"" FIELD_SEP "access=0x%x" FIELD_SEP "share=0x%x" FIELD_SEP "attr=0x%x" FIELD_SEP "cd=0x%x" FIELD_SEP "co=0x%x\n",
				event->path,
				event->file_create.desired_access,
				event->file_create.share_mode,
				event->file_create.attributes,
				event->file_create.creation_disposition,
				event->file_create.create_options);
		break;
	case ET_FILE_CLOSE:
		printf("close:" FIELD_SEP "\"%S\"\n", event->path);
		break;
	case ET_FILE_READ:
		printf("read:" FIELD_SEP "\"%S\"" FIELD_SEP "%I64u+%lu\n",
				event->path,
				event->file_rw.offset.QuadPart,
				event->file_rw.length);
		break;
	case ET_FILE_WRITE:
		printf("write:" FIELD_SEP "\"%S\"" FIELD_SEP "%I64u+%lu\n",
				event->path,
				event->file_rw.offset.QuadPart,
				event->file_rw.length);
		break;
	case ET_FILE_CREATE_MAILSLOT:
		printf("mslot:" FIELD_SEP "\"%S\"\n", event->path);
		break;
	case ET_FILE_CREATE_NAMED_PIPE:
		printf("pipe:" FIELD_SEP "\"%S\"\n", event->path);
		break;
	case ET_FILE_QUERY_INFORMATION:
		switch (event->file_info.info_type) {
		case FileAllInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileAllInformation" FIELD_SEP "s=%d\n",
					event->path,
					event->file_info.info_size);
			break;
		case FileAttributeTagInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileAttributeTagInformation" FIELD_SEP "attr=0x%x" FIELD_SEP "tag=0x%x\n",
					event->path,
					event->file_info.info_data.file_info_attribute_tag.file_attributes,
					event->file_info.info_data.file_info_attribute_tag.reparse_tag);
			break;
		case FileBasicInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileBasicInformation" FIELD_SEP "ct=%I64u" FIELD_SEP "lat=%I64u" FIELD_SEP "lwt=%I64u" FIELD_SEP "lct=%I64u" FIELD_SEP "attr=0x%x\n",
					event->path,
					event->file_info.info_data.file_info_basic.creation_time,
					event->file_info.info_data.file_info_basic.last_access_time,
					event->file_info.info_data.file_info_basic.last_write_time,
					event->file_info.info_data.file_info_basic.change_time,
					event->file_info.info_data.file_info_basic.file_attributes);
			break;
		case FileCompressionInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileCompressionInformation" FIELD_SEP "size=%I64u" FIELD_SEP "format=%d" FIELD_SEP "unit=%d" FIELD_SEP "chunk=%d" FIELD_SEP "cluster=%d" FIELD_SEP "reserved=%d,%d,%d\n",
					event->path,
					event->file_info.info_data.file_info_compression.compressed_file_size,
					event->file_info.info_data.file_info_compression.compression_format,
					event->file_info.info_data.file_info_compression.compression_unit_shift,
					event->file_info.info_data.file_info_compression.chunk_shift,
					event->file_info.info_data.file_info_compression.cluster_shift,
					event->file_info.info_data.file_info_compression.reserved[0],
					event->file_info.info_data.file_info_compression.reserved[1],
					event->file_info.info_data.file_info_compression.reserved[2]);
			break;
		case FileEaInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileEaInformation" FIELD_SEP "size=%d\n",
					event->path,
					event->file_info.info_data.file_info_ea.ea_size);
			break;
		case FileInternalInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileInternalInformation" FIELD_SEP "index=%I64u\n",
					event->path,
					event->file_info.info_data.file_info_internal.index_number);
			break;
		case FileNameInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileNameInformation" FIELD_SEP "name=\"%S\"\n",
					event->path,
					event->file_info.info_data.file_info_name.file_name);
			break;
		case FileNetworkOpenInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileNetworkOpenInformation" FIELD_SEP "ct=%I64u" FIELD_SEP "lat=%I64u" FIELD_SEP "lwt=%I64u" FIELD_SEP "lct=%I64u" FIELD_SEP "as=%I64u" FIELD_SEP "eof=%I64u" FIELD_SEP "attr=0x%x\n",
					event->path,
					event->file_info.info_data.file_info_network_open.creation_time,
					event->file_info.info_data.file_info_network_open.last_access_time,
					event->file_info.info_data.file_info_network_open.last_write_time,
					event->file_info.info_data.file_info_network_open.change_time,
					event->file_info.info_data.file_info_network_open.allocation_size,
					event->file_info.info_data.file_info_network_open.end_of_file,
					event->file_info.info_data.file_info_network_open.file_attributes);
			break;
		case FilePositionInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FilePositionInformation" FIELD_SEP "pos=%I64u\n",
					event->path,
					event->file_info.info_data.file_info_position.current_byte_offset);
			break;
		case FileStandardInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileStandardInformation" FIELD_SEP "as=%I64u" FIELD_SEP "eof=%I64u" FIELD_SEP "links=%d" FIELD_SEP "delete=%s" FIELD_SEP "dir=%s\n",
					event->path,
					event->file_info.info_data.file_info_standard.allocation_size,
					event->file_info.info_data.file_info_standard.end_of_file,
					event->file_info.info_data.file_info_standard.number_of_links,
					event->file_info.info_data.file_info_standard.delete_pending ? "true" : "false",
					event->file_info.info_data.file_info_standard.directory ? "true" : "false");
			break;
		case FileStreamInformation:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileStreamInformation" FIELD_SEP "next=%lu" FIELD_SEP "size=%I64u" FIELD_SEP "as=%I64u" FIELD_SEP "name=\"%S\"\n",
					event->path,
					event->file_info.info_data.file_info_stream.next_entry_offset,
					event->file_info.info_data.file_info_stream.stream_size,
					event->file_info.info_data.file_info_stream.stream_allocation_size,
					event->file_info.info_data.file_info_stream.stream_name);
			break;
		default:
			printf("queryinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=%d" FIELD_SEP "s=%d\n",
					event->path,
					event->file_info.info_type,
					event->file_info.info_size);
		}
		break;
	case ET_FILE_SET_INFORMATION:
		switch (event->file_info.info_type) {
		case FileAllocationInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileAllocationInformation" FIELD_SEP "AllocationSize=%I64u\n",
					event->path,
					event->file_info.info_data.file_info_allocation.allocation_size);
			break;
		case FileBasicInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileBasicInformation" FIELD_SEP "ct=%I64u" FIELD_SEP "lat=%I64u" FIELD_SEP "lwt=%I64u" FIELD_SEP "lct=%I64u" FIELD_SEP "attr=0x%x\n",
					event->path,
					event->file_info.info_data.file_info_basic.creation_time,
					event->file_info.info_data.file_info_basic.last_access_time,
					event->file_info.info_data.file_info_basic.last_write_time,
					event->file_info.info_data.file_info_basic.change_time,
					event->file_info.info_data.file_info_basic.file_attributes);
			break;
		case FileDispositionInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileDispositionInformation" FIELD_SEP "delete=%s\n",
					event->path,
					event->file_info.info_data.file_info_disposition.delete_file ? "true" : "false");
			break;
		case FileEndOfFileInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileEndOfFileInformation" FIELD_SEP "end=%I64u\n",
					event->path,
					event->file_info.info_data.file_info_end_of_file.end_of_file);
			break;
		case FileLinkInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileLinkInformation" FIELD_SEP "replace=%s" FIELD_SEP "root=0x%x" FIELD_SEP "name=\"%S\"\n",
					event->path,
					event->file_info.info_data.file_info_link.replace_if_exists ? "true" : "false",
					event->file_info.info_data.file_info_link.root_directory,
					event->file_info.info_data.file_info_link.file_name);
			break;
		case FilePositionInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FilePositionInformation" FIELD_SEP "pos=%I64u\n",
					event->path,
					event->file_info.info_data.file_info_position.current_byte_offset);
			break;
		case FileRenameInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileRenameInformation" FIELD_SEP "replace=%s" FIELD_SEP "root=0x%x" FIELD_SEP "name=\"%S\"\n",
					event->path,
					event->file_info.info_data.file_info_rename.replace_if_exists ? "true" : "false",
					event->file_info.info_data.file_info_rename.root_directory,
					event->file_info.info_data.file_info_rename.file_name);
			break;
		case FileValidDataLengthInformation:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=FileValidDataLengthInformation" FIELD_SEP "len=%I64u\n",
					event->path,
					event->file_info.info_data.file_info_valid_data_length.valid_data_length);
			break;
		default:
			printf("setinfo:" FIELD_SEP "\"%S\"" FIELD_SEP "t=%d" FIELD_SEP "s=%d\n",
					event->path,
					event->file_info.info_type,
					event->file_info.info_size);
		}
		break;
	case ET_REG_CLOSE:
		printf("reg_close:" FIELD_SEP "\"%S\"" FIELD_SEP "0x%x\n",
				event->path,
				event->reg_close.handle);
		break;
	case ET_REG_CREATE:
		printf("reg_create:" FIELD_SEP "\"%S\"" FIELD_SEP "hd=0x%x" FIELD_SEP "da=0x%x" FIELD_SEP "co=0x%x" FIELD_SEP "cd=0x%x\n",
				event->path,
				event->reg_create.handle,
				event->reg_create.desired_access,
				event->reg_create.create_options,
				event->reg_create.creation_disposition);
		break;
	case ET_REG_DELETE:
		printf("reg_delete:" FIELD_SEP "\"%S\"" FIELD_SEP "0x%x\n",
				event->path,
				event->reg_delete.handle);
		break;
	case ET_REG_DELETEVALUE:
		printf("reg_deletevalue:" FIELD_SEP "\"%S\"" FIELD_SEP "0x%x\n",
				event->path,
				event->reg_delete_value.handle);
		break;
	case ET_REG_OPEN:
		printf("reg_open:" FIELD_SEP "\"%S\"" FIELD_SEP "0x%x" FIELD_SEP "0x%x\n",
				event->path,
				event->reg_open.handle,
				event->reg_open.desired_access);
		break;
	case ET_REG_QUERYVALUE:
	case ET_REG_SETVALUE:
		switch (event->reg_rw.value_type) {
		case REG_BINARY:
			printf("reg_%svalue:" FIELD_SEP "\"%S\"" FIELD_SEP "t=REG_BINARY" FIELD_SEP "l=%d\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					event->reg_rw.value_length);
			break;
		case REG_DWORD:
			printf("reg_%svalue:" FIELD_SEP "\"%S\"" FIELD_SEP "t=REG_DWORD" FIELD_SEP "v=0x%x\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					*(unsigned int *)event->reg_rw.value);
			break;
		case REG_EXPAND_SZ:
			printf("reg_%svalue:" FIELD_SEP "\"%S\"" FIELD_SEP "t=REG_EXPAND_SZ" FIELD_SEP "l=%d" FIELD_SEP "v=\"%S\"\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					event->reg_rw.value_length,
					event->reg_rw.value);
			break;
		case REG_SZ:
			printf("reg_%svalue:" FIELD_SEP "\"%S\"" FIELD_SEP "t=REG_SZ" FIELD_SEP "l=%d" FIELD_SEP "v=\"%S\"\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					event->reg_rw.value_length,
					event->reg_rw.value);
			break;
		default:
			printf("reg_%svalue:" FIELD_SEP "\"%S\"" FIELD_SEP "t=0x%x" FIELD_SEP "l=%d\n",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					event->reg_rw.value_type,
					event->reg_rw.value_length);
		}
		break;
	case ET_PROC_PROC_CREATE:
		printf("proc_create:" FIELD_SEP "ppid=%d" FIELD_SEP "pid=%d\n",
				event->proc_proc_create.ppid,
				event->proc_proc_create.pid);
		break;
	case ET_PROC_PROC_TERM:
		printf("proc_term:" FIELD_SEP "ppid=%d" FIELD_SEP "pid=%d\n",
				event->proc_proc_term.ppid,
				event->proc_proc_term.pid);
		break;
	case ET_PROC_THREAD_CREATE:
		printf("thread_create:" FIELD_SEP "tid=%d\n",
				event->proc_thread_create.tid);
		break;
	case ET_PROC_THREAD_TERM:
		printf("thread_term:" FIELD_SEP "tid=%d\n",
				event->proc_thread_create.tid);
		break;
	case ET_PROC_IMAGE:
		printf("image:" FIELD_SEP "\"%S\"" FIELD_SEP "%d" FIELD_SEP "0x%08x" FIELD_SEP "%d\n",
				event->path,
				event->proc_image.system,
				event->proc_image.base,
				event->proc_image.size);
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
