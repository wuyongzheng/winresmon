#include <windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include "zlib/zlib.h"
#include "kucomm.h"

DWORD WINAPI GetModuleFileNameExA (HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

#define PHASH_SIZE 198 // again, a bus number
#define FIELD_SEP "\t"
#define PARAM_SEP ", "

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

#define TDI_QUERY_BROADCAST_ADDRESS      0x00000001
#define TDI_QUERY_PROVIDER_INFO          0x00000002
#define TDI_QUERY_ADDRESS_INFO           0x00000003
#define TDI_QUERY_CONNECTION_INFO        0x00000004
#define TDI_QUERY_PROVIDER_STATISTICS    0x00000005
#define TDI_QUERY_DATAGRAM_INFO          0x00000006
#define TDI_QUERY_DATA_LINK_ADDRESS      0x00000007
#define TDI_QUERY_NETWORK_ADDRESS        0x00000008
#define TDI_QUERY_MAX_DATAGRAM_INFO      0x00000009
#define TDI_QUERY_ROUTING_INFO           0x0000000a

extern const char *get_ntstatus_name (long status);

struct proc_info {
	struct proc_info *htable_next;
	unsigned long pid;
	unsigned int deleting_age; // for deleting proc. this is the serial of proc_term
	struct proc_info *deleting_next;
	char name[MAX_PATH_SIZE];
	char owner[MAX_PATH_SIZE];
};

static int config_service_enable_gzip = 1;
static int config_console_enable_gzip = 0;
static int config_service_wait = 1000;
static int config_console_wait = 500;

static HANDLE stop_event;
static HANDLE driver_file;
static HANDLE ready_event;
static HANDLE section;
static struct event_buffer *event_buffer;
static FILE *out_file;
static int (*out_fprintf)(FILE *stream, const char *format, ...);
static struct proc_info *proc_hashtable[PHASH_SIZE];
static struct proc_info *deleting_head, *deleting_tail;

static void phash_remove (unsigned long pid)
{
	struct proc_info *proc = proc_hashtable[pid % PHASH_SIZE];

	if (proc == NULL)
		return;
	if (proc->pid == pid) {
		proc_hashtable[pid % PHASH_SIZE] = proc->htable_next;
		free(proc);
		return;
	}
	for (; proc->htable_next != NULL; proc = proc->htable_next) {
		if (proc->htable_next->pid == pid) {
			struct proc_info *tmp = proc->htable_next;
			proc->htable_next = tmp->htable_next;
			free(tmp);
			return;
		}
	}
}

static void phash_term (unsigned long pid, unsigned age)
{
	struct proc_info *proc = proc_hashtable[pid % PHASH_SIZE];
	while (proc != NULL) {
		if (proc->pid == pid) {
			proc->deleting_age = age;
			if (deleting_head == NULL) {
				deleting_head = deleting_tail = proc;
			} else {
				deleting_tail = deleting_tail->deleting_next = proc;
			}
			proc->deleting_next = NULL;
			break;
		}
		proc = proc->htable_next;
	}
}

static void phash_query (struct proc_info *proc)
{
	HANDLE process, token;
	char owner_buffer[16384]; // strange thing found in http://win32.mvps.org/security/opt_gti.cpp
	TOKEN_USER *owner = (TOKEN_USER *)owner_buffer;
	int owner_size;
	char account[256], domain[256];
	int account_size = sizeof(account), domain_size = sizeof(domain);
	SID_NAME_USE type;

	proc->name[0] = proc->owner[0] = '?';
	proc->name[1] = proc->owner[1] = '\0';

	process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc->pid);
	if (process == NULL)
		return;

	if (!GetModuleFileNameExA(process, NULL, proc->name, sizeof(proc->name))) {
		if (proc->pid == 4) { // hard-code pid 4
			sprintf_s(proc->name, sizeof(proc->name), "System");
		} else {
			proc->name[0] = '?';
			proc->name[1] = '\0';
		}
	}
	if (strncmp(proc->name, "\\??\\", 4) == 0)
		memmove(proc->name, proc->name + 4, strlen(proc->name) - 3);

	if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
		if (GetTokenInformation(token, TokenUser, owner, sizeof(owner_buffer), &owner_size)) {
			if (LookupAccountSid(NULL, owner->User.Sid, account, &account_size, domain, &domain_size, &type)) {
				sprintf_s(proc->owner, sizeof(proc->owner), "%s\\%s", domain, account);
			}
		}
		CloseHandle(token);
	}

	CloseHandle(process);
}

static struct proc_info *phash_get (unsigned long pid)
{
	struct proc_info *curr;

	for (curr = proc_hashtable[pid % PHASH_SIZE]; curr != NULL; curr = curr->htable_next)
		if (curr->pid == pid)
			return curr;

	curr = (struct proc_info *)malloc(sizeof(struct proc_info));
	curr->pid = pid;
	curr->htable_next = proc_hashtable[pid % PHASH_SIZE];
	curr->deleting_age = 0;
	curr->deleting_next = NULL;
	proc_hashtable[pid % PHASH_SIZE] = curr;
	phash_query(curr);

	return curr;
}

static void phash_init (void)
{
	int i;
	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;

	for (i = 0; i < PHASH_SIZE; i ++)
		proc_hashtable[i] = NULL;
	deleting_head = deleting_tail = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		OutputDebugString("OpenProcessToken(curr) error.\n");
		return;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug)) {
		OutputDebugString("LookupPrivilegeValue() error.\n");
		CloseHandle(hToken);
		return;
	}

	tokenPriv.PrivilegeCount           = 1;
	tokenPriv.Privileges[0].Luid       = luidDebug;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL)) {
		OutputDebugString("AdjustTokenPrivileges() error.\n");
	}

	CloseHandle(hToken);
}

static const char *print_binary (const unsigned char *data, int length)
{
	static char buff[MAX_IO_SIZE + 3];
	int i;

	if (length > MAX_IO_SIZE)
		length = MAX_IO_SIZE;

	buff[0] = '"';
	for (i = 0; i < length; i ++) {
		if (data[i] < ' ' || data[i] == '"' || data[i] > '~')
			buff[i + 1] = '.';
		else
			buff[i + 1] = data[i];
	}
	buff[length + 1] = '"';
	buff[length + 2] = '\0';

	return buff;
}

static const short *filter_wstring (const short *str, int length)
{
	static short buff[MAX_PATH_SIZE];
	int i;

	if (length > MAX_PATH_SIZE - 1)
		length = MAX_PATH_SIZE - 1;

	for (i = 0; i < length; i ++)
		if (str[i] == L'\r' || str[i] == L'\n' || str[i] == L'\t' || str[i] == L'\"')
			break;

	if (i == length) {
		if (str[length] == L'\0') {
			return str;
		} else {
			memcpy(buff, str, length);
			buff[length] = L'\0';
		}
	} else {
		for (i = 0; i < length; i ++) {
			if (str[i] == L'\r' || str[i] == L'\n' || str[i] == L'\t' || str[i] == L'\"')
				buff[i] = L' ';
			else
				buff[i] = str[i];
		}
		buff[length] = L'\0';
	}

	return buff;
}

static unsigned short my_ntohs (unsigned short netshort)
{
	unsigned short result = 0;
	((char *)&result)[0] = ((char *)&netshort)[1];
	((char *)&result)[1] = ((char *)&netshort)[0];
	return result;
}

static const char *print_tdi_transport_address (const struct tdi_transport_address *addr)
{
	static char buffer[4][32];
	static unsigned int buffer_count = 0;
	char *this_buffer = buffer[(buffer_count ++) % 4];

	switch (addr->family) {
	case 0:
		strncpy(this_buffer, "null", 32);
		break;
	case 2:
		sprintf_s(this_buffer, 32, "%u.%u.%u.%u:%u",
				addr->ipv4.addr[0], addr->ipv4.addr[1],
				addr->ipv4.addr[2], addr->ipv4.addr[3],
				my_ntohs(addr->ipv4.port));
		break;
	case 23:
		sprintf_s(this_buffer, 32, "ipv6"); //TODO
		break;
	default:
		sprintf_s(this_buffer, 32, "%d", addr->family);
	}

	return this_buffer;
}

static void process_event (const struct event *event)
{
	struct proc_info *proc;

	if (event->type == ET_IGNORE)
		return;

	proc = phash_get(event->pid);
	if (proc->name[0] == '?' && proc->name[1] == '\0' &&
			event->type == ET_PROC_IMAGE) {
		sprintf_s(proc->name, sizeof(proc->name), "%S", event->path);
	}

	out_fprintf(out_file, "%u" FIELD_SEP "%I64u" FIELD_SEP "%I64u" FIELD_SEP "%d" FIELD_SEP "%d" FIELD_SEP
			"%s" FIELD_SEP "%s" FIELD_SEP "%s" FIELD_SEP,
			event->serial, event->time_pre.QuadPart, event->time_post.QuadPart, event->pid, event->tid,
			proc->name, proc->owner, get_ntstatus_name(event->status));

	switch (event->type) {
	case ET_FILE_CREATE:
		out_fprintf(out_file, "file_create" FIELD_SEP "%S" FIELD_SEP
				"access=0x%x" PARAM_SEP "share=0x%x" PARAM_SEP "attr=0x%x" PARAM_SEP
				"cd=0x%x" PARAM_SEP "co=0x%x" PARAM_SEP "si=0x%x",
				event->path,
				event->file_create.desired_access,
				event->file_create.share_mode,
				event->file_create.attributes,
				event->file_create.creation_disposition,
				event->file_create.create_options,
				event->file_create.status_information);
		break;
	case ET_FILE_CLOSE:
		out_fprintf(out_file, "file_close" FIELD_SEP "%S" FIELD_SEP "", event->path);
		break;
	case ET_FILE_READ:
		out_fprintf(out_file, "file_read" FIELD_SEP "%S" FIELD_SEP "addr=%I64u" PARAM_SEP "reqs=%lu" PARAM_SEP "rets=%lu",
				event->path,
				event->file_rw.offset.QuadPart,
				event->file_rw.req_length,
				event->file_rw.ret_length);
		break;
	case ET_FILE_WRITE:
		out_fprintf(out_file, "file_write" FIELD_SEP "%S" FIELD_SEP "addr=%I64u" PARAM_SEP "reqs=%lu" PARAM_SEP "rets=%lu",
				event->path,
				event->file_rw.offset.QuadPart,
				event->file_rw.req_length,
				event->file_rw.ret_length);
		break;
	case ET_FILE_CREATE_MAILSLOT:
		out_fprintf(out_file, "file_mslot" FIELD_SEP "%S", event->path);
		break;
	case ET_FILE_CREATE_NAMED_PIPE:
		out_fprintf(out_file, "file_pipe" FIELD_SEP "%S", event->path);
		break;
	case ET_FILE_QUERY_INFORMATION:
		switch (event->file_info.info_type) {
		case FileAllInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileAllInformation" PARAM_SEP "s=%d",
					event->path,
					event->file_info.info_size);
			break;
		case FileAttributeTagInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileAttributeTagInformation" PARAM_SEP "attr=0x%x" PARAM_SEP "tag=0x%x",
					event->path,
					event->file_info.info_data.file_info_attribute_tag.file_attributes,
					event->file_info.info_data.file_info_attribute_tag.reparse_tag);
			break;
		case FileBasicInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileBasicInformation" PARAM_SEP "ct=%I64u" PARAM_SEP "lat=%I64u" PARAM_SEP
					"lwt=%I64u" PARAM_SEP "lct=%I64u" PARAM_SEP "attr=0x%x",
					event->path,
					event->file_info.info_data.file_info_basic.creation_time,
					event->file_info.info_data.file_info_basic.last_access_time,
					event->file_info.info_data.file_info_basic.last_write_time,
					event->file_info.info_data.file_info_basic.change_time,
					event->file_info.info_data.file_info_basic.file_attributes);
			break;
		case FileCompressionInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileCompressionInformation" PARAM_SEP "size=%I64u" PARAM_SEP
					"format=%d" PARAM_SEP "unit=%d" PARAM_SEP "chunk=%d" PARAM_SEP
					"cluster=%d" PARAM_SEP "reserved=%d,%d,%d",
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
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileEaInformation" PARAM_SEP "size=%d",
					event->path,
					event->file_info.info_data.file_info_ea.ea_size);
			break;
		case FileInternalInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileInternalInformation" PARAM_SEP "index=%I64u",
					event->path,
					event->file_info.info_data.file_info_internal.index_number);
			break;
		case FileNameInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileNameInformation" PARAM_SEP "name=\"%S\"",
					event->path,
					filter_wstring(event->file_info.info_data.file_info_name.file_name,
						event->file_info.info_data.file_info_name.file_name_length));
			break;
		case FileNetworkOpenInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileNetworkOpenInformation" PARAM_SEP "ct=%I64u" PARAM_SEP
					"lat=%I64u" PARAM_SEP "lwt=%I64u" PARAM_SEP "lct=%I64u" PARAM_SEP
					"as=%I64u" PARAM_SEP "eof=%I64u" PARAM_SEP "attr=0x%x",
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
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FilePositionInformation" PARAM_SEP "pos=%I64u",
					event->path,
					event->file_info.info_data.file_info_position.current_byte_offset);
			break;
		case FileStandardInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileStandardInformation" PARAM_SEP "as=%I64u" PARAM_SEP "eof=%I64u" PARAM_SEP
					"links=%d" PARAM_SEP "delete=%s" PARAM_SEP "dir=%s",
					event->path,
					event->file_info.info_data.file_info_standard.allocation_size,
					event->file_info.info_data.file_info_standard.end_of_file,
					event->file_info.info_data.file_info_standard.number_of_links,
					event->file_info.info_data.file_info_standard.delete_pending ? "true" : "false",
					event->file_info.info_data.file_info_standard.directory ? "true" : "false"); //TODO check correctness
			break;
		case FileStreamInformation:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileStreamInformation" PARAM_SEP "next=%lu" PARAM_SEP "size=%I64u" PARAM_SEP
					"as=%I64u" PARAM_SEP "name=\"%S\"",
					event->path,
					event->file_info.info_data.file_info_stream.next_entry_offset,
					event->file_info.info_data.file_info_stream.stream_size,
					event->file_info.info_data.file_info_stream.stream_allocation_size,
					filter_wstring(event->file_info.info_data.file_info_stream.stream_name, event->file_info.info_data.file_info_stream.stream_name_length));
			break;
		default:
			out_fprintf(out_file, "file_queryinfo" FIELD_SEP "%S" FIELD_SEP "t=%d" PARAM_SEP "s=%d",
					event->path,
					event->file_info.info_type,
					event->file_info.info_size);
		}
		break;
	case ET_FILE_SET_INFORMATION:
		switch (event->file_info.info_type) {
		case FileAllocationInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileAllocationInformation" PARAM_SEP "as=%I64u",
					event->path,
					event->file_info.info_data.file_info_allocation.allocation_size);
			break;
		case FileBasicInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileBasicInformation" PARAM_SEP "ct=%I64u" PARAM_SEP "lat=%I64u" PARAM_SEP
					"lwt=%I64u" PARAM_SEP "lct=%I64u" PARAM_SEP "attr=0x%x",
					event->path,
					event->file_info.info_data.file_info_basic.creation_time,
					event->file_info.info_data.file_info_basic.last_access_time,
					event->file_info.info_data.file_info_basic.last_write_time,
					event->file_info.info_data.file_info_basic.change_time,
					event->file_info.info_data.file_info_basic.file_attributes);
			break;
		case FileDispositionInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileDispositionInformation" PARAM_SEP "delete=%s",
					event->path,
					event->file_info.info_data.file_info_disposition.delete_file ? "true" : "false");
			break;
		case FileEndOfFileInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileEndOfFileInformation" PARAM_SEP "end=%I64u",
					event->path,
					event->file_info.info_data.file_info_end_of_file.end_of_file);
			break;
		case FileLinkInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileLinkInformation" PARAM_SEP "replace=%s" PARAM_SEP
					"root=0x%x" PARAM_SEP "name=\"%S\"",
					event->path,
					event->file_info.info_data.file_info_link.replace_if_exists ? "true" : "false",
					event->file_info.info_data.file_info_link.root_directory,
					filter_wstring(event->file_info.info_data.file_info_link.file_name, event->file_info.info_data.file_info_link.file_name_length));
			break;
		case FilePositionInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FilePositionInformation" PARAM_SEP "pos=%I64u",
					event->path,
					event->file_info.info_data.file_info_position.current_byte_offset);
			break;
		case FileRenameInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileRenameInformation" PARAM_SEP "replace=%s" PARAM_SEP "root=0x%x" PARAM_SEP
					"name=\"%S\"",
					event->path,
					event->file_info.info_data.file_info_rename.replace_if_exists ? "true" : "false",
					event->file_info.info_data.file_info_rename.root_directory,
					filter_wstring(event->file_info.info_data.file_info_rename.file_name, event->file_info.info_data.file_info_rename.file_name_length));
			break;
		case FileValidDataLengthInformation:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=FileValidDataLengthInformation" PARAM_SEP "len=%I64u",
					event->path,
					event->file_info.info_data.file_info_valid_data_length.valid_data_length);
			break;
		default:
			out_fprintf(out_file, "file_setinfo" FIELD_SEP "%S" FIELD_SEP
					"t=%d" PARAM_SEP "s=%d",
					event->path,
					event->file_info.info_type,
					event->file_info.info_size);
		}
		break;
	case ET_REG_CLOSE:
		out_fprintf(out_file, "reg_close" FIELD_SEP "%S" FIELD_SEP "handle=0x%x",
				event->path,
				event->reg_close.handle);
		break;
	case ET_REG_CREATE:
		out_fprintf(out_file, "reg_create" FIELD_SEP "%S" FIELD_SEP
				"hd=0x%x" PARAM_SEP "da=0x%x" PARAM_SEP "co=0x%x" PARAM_SEP "cd=0x%x",
				event->path,
				event->reg_create.handle,
				event->reg_create.desired_access,
				event->reg_create.create_options,
				event->reg_create.creation_disposition);
		break;
	case ET_REG_DELETE:
		out_fprintf(out_file, "reg_delete" FIELD_SEP "%S" FIELD_SEP "handle=0x%x",
				event->path,
				event->reg_delete.handle);
		break;
	case ET_REG_DELETEVALUE:
		out_fprintf(out_file, "reg_deletevalue" FIELD_SEP "%S" FIELD_SEP "handle=0x%x",
				event->path,
				event->reg_delete_value.handle);
		break;
	case ET_REG_OPEN:
		out_fprintf(out_file, "reg_open" FIELD_SEP "%S" FIELD_SEP "handle=0x%x" PARAM_SEP "access=0x%x",
				event->path,
				event->reg_open.handle,
				event->reg_open.desired_access);
		break;
	case ET_REG_QUERYVALUE:
	case ET_REG_SETVALUE:
		switch (event->reg_rw.value_type) {
		case REG_BINARY:
			out_fprintf(out_file, "reg_%svalue" FIELD_SEP "%S" FIELD_SEP "t=REG_BINARY" PARAM_SEP "l=%d",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					event->reg_rw.value_length);
			break;
		case REG_DWORD:
			out_fprintf(out_file, "reg_%svalue" FIELD_SEP "%S" FIELD_SEP "t=REG_DWORD" PARAM_SEP "v=0x%x",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					*(unsigned int *)event->reg_rw.value);
			break;
		case REG_EXPAND_SZ:
			out_fprintf(out_file, "reg_%svalue" FIELD_SEP "%S" FIELD_SEP "t=REG_EXPAND_SZ" PARAM_SEP "v=\"%S\"",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					filter_wstring((const short *)event->reg_rw.value, event->reg_rw.value_length / 2));
			break;
		case REG_SZ:
			out_fprintf(out_file, "reg_%svalue" FIELD_SEP "%S" FIELD_SEP "t=REG_SZ" PARAM_SEP "v=\"%S\"",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					filter_wstring((const short *)event->reg_rw.value, event->reg_rw.value_length / 2));
			break;
		default:
			out_fprintf(out_file, "reg_%svalue" FIELD_SEP "%S" FIELD_SEP "t=0x%x" PARAM_SEP "l=%d",
					event->type == ET_REG_QUERYVALUE ? "query" : "set",
					event->path,
					event->reg_rw.value_type,
					event->reg_rw.value_length);
		}
		break;
	case ET_PROC_PROC_CREATE:
		out_fprintf(out_file, "proc_create" FIELD_SEP "" FIELD_SEP "ppid=%d" PARAM_SEP "pid=%d",
				event->proc_proc_create.ppid,
				event->proc_proc_create.pid);
		break;
	case ET_PROC_PROC_TERM:
		out_fprintf(out_file, "proc_term" FIELD_SEP "" FIELD_SEP "ppid=%d" PARAM_SEP "pid=%d",
				event->proc_proc_term.ppid,
				event->proc_proc_term.pid);
		phash_term(event->pid, event->serial);
		break;
	case ET_PROC_THREAD_CREATE:
		out_fprintf(out_file, "thread_create" FIELD_SEP "" FIELD_SEP "tid=%d",
				event->proc_thread_create.tid);
		break;
	case ET_PROC_THREAD_TERM:
		out_fprintf(out_file, "thread_term" FIELD_SEP "" FIELD_SEP "tid=%d",
				event->proc_thread_term.tid);
		break;
	case ET_PROC_IMAGE:
		out_fprintf(out_file, "image" FIELD_SEP "%S" FIELD_SEP
				"system=%s" PARAM_SEP "base=0x%08x" PARAM_SEP "size=0x%x",
				event->path,
				event->proc_image.system ? "true" : "false",
				event->proc_image.base,
				event->proc_image.size);
		break;
	case ET_TDI_CLEANUP:
		out_fprintf(out_file, "tdi_cleanup" FIELD_SEP FIELD_SEP "f=0x%x",
				event->tdi_general.file_object);
		break;
	case ET_TDI_CLOSE:
		out_fprintf(out_file, "tdi_close" FIELD_SEP FIELD_SEP "f=0x%x",
				event->tdi_general.file_object);
		break;
	case ET_TDI_CREATE:
		out_fprintf(out_file, "tdi_create" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "type=%s" PARAM_SEP "addr=%s",
				event->tdi_create.file_object,
				event->tdi_create.type == 1 ? "control" :
				event->tdi_create.type == 2 ? "address" : "connection",
				print_tdi_transport_address(&event->tdi_create.addr));
		break;
	case ET_TDI_ACCEPT:
		out_fprintf(out_file, "tdi_accept" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "reqaddr=%s" PARAM_SEP "retaddr=%s",
				event->tdi_accept.file_object,
				print_tdi_transport_address(&event->tdi_accept.request_addr),
				print_tdi_transport_address(&event->tdi_accept.return_addr));
		break;
	case ET_TDI_ACTION:
		out_fprintf(out_file, "tdi_action" FIELD_SEP FIELD_SEP "f=0x%x",
				event->tdi_general.file_object);
		break;
	case ET_TDI_ASSOCIATE_ADDRESS:
		out_fprintf(out_file, "tdi_associate_address" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "f2=0x%x",
				event->tdi_associate_address.file_object,
				event->tdi_associate_address.file_object2);
		break;
	case ET_TDI_CONNECT:
		out_fprintf(out_file, "tdi_connect" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "reqaddr=%s" PARAM_SEP "retaddr=%s" PARAM_SEP "to=%I64u",
				event->tdi_connect.file_object,
				print_tdi_transport_address(&event->tdi_connect.request_addr),
				print_tdi_transport_address(&event->tdi_connect.return_addr),
				event->tdi_connect.timeout);
		break;
	case ET_TDI_DISASSOCIATE_ADDRESS:
		out_fprintf(out_file, "tdi_disassociate_address" FIELD_SEP FIELD_SEP "f=0x%x",
				event->tdi_general.file_object);
		break;
	case ET_TDI_DISCONNECT:
		out_fprintf(out_file, "tdi_disconnect" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "flags=0x%x" PARAM_SEP
				"reqaddr=%s" PARAM_SEP "retaddr=%s" PARAM_SEP "to=%I64u",
				event->tdi_disconnect.file_object,
				event->tdi_disconnect.flags,
				print_tdi_transport_address(&event->tdi_disconnect.request_addr),
				print_tdi_transport_address(&event->tdi_disconnect.return_addr),
				event->tdi_disconnect.timeout);
		break;
	case ET_TDI_LISTEN:
		out_fprintf(out_file, "tdi_listen" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "flags=0x%x" PARAM_SEP "reqaddr=%s" PARAM_SEP "retaddr=%s",
				event->tdi_listen.file_object,
				event->tdi_listen.flags,
				print_tdi_transport_address(&event->tdi_listen.request_addr),
				print_tdi_transport_address(&event->tdi_listen.return_addr));
		break;
	case ET_TDI_QUERY_INFORMATION:
	case ET_TDI_SET_INFORMATION:
		switch (event->tdi_query_information.type) {
		case TDI_QUERY_ADDRESS_INFO:
			out_fprintf(out_file, "%s" FIELD_SEP FIELD_SEP
					"f=0x%x" PARAM_SEP "type=address" PARAM_SEP "addr=%s" PARAM_SEP
					"info_ac=%u" PARAM_SEP "info_addr=%s",
					event->type == ET_TDI_QUERY_INFORMATION ? "tdi_query_information" : "tdi_set_information",
					event->tdi_query_information.file_object,
					print_tdi_transport_address(&event->tdi_query_information.addr),
					event->tdi_query_information.address.activity_count,
					print_tdi_transport_address(&event->tdi_query_information.address.addr));
			break;
		case TDI_QUERY_CONNECTION_INFO:
			out_fprintf(out_file, "%s" FIELD_SEP FIELD_SEP
					"f=0x%x" PARAM_SEP "type=address" PARAM_SEP "addr=%s" PARAM_SEP
					"info_status=%u" PARAM_SEP "info_event=%u" PARAM_SEP "info_tt=%u" PARAM_SEP
					"info_rt=%u" PARAM_SEP "info_te=%u" PARAM_SEP "info_re=%u" PARAM_SEP
					"info_throughput=%I64d" PARAM_SEP "info_delay=%I64d" PARAM_SEP
					"info_sbs=%u" PARAM_SEP "info_rbs=%u" PARAM_SEP "info_unreliable=%s",
					event->type == ET_TDI_QUERY_INFORMATION ? "tdi_query_information" : "tdi_set_information",
					event->tdi_query_information.file_object,
					print_tdi_transport_address(&event->tdi_query_information.addr),
					event->tdi_query_information.connection.status,
					event->tdi_query_information.connection.event,
					event->tdi_query_information.connection.transmitted_tsdus,
					event->tdi_query_information.connection.received_tsdus,
					event->tdi_query_information.connection.transmission_errors,
					event->tdi_query_information.connection.receive_errors,
					event->tdi_query_information.connection.throughput,
					event->tdi_query_information.connection.delay,
					event->tdi_query_information.connection.send_buffer_size,
					event->tdi_query_information.connection.receive_buffer_size,
					event->tdi_query_information.connection.unreliable ? "yes" : "no");
			break;
		default:
			out_fprintf(out_file, "%s" FIELD_SEP FIELD_SEP
					"f=0x%x" PARAM_SEP "type=%d" PARAM_SEP "addr=%s",
					event->type == ET_TDI_QUERY_INFORMATION ? "tdi_query_information" : "tdi_set_information",
					event->tdi_query_information.file_object,
					event->tdi_query_information.type,
					print_tdi_transport_address(&event->tdi_query_information.addr));
		}
		break;
	case ET_TDI_RECEIVE:
		out_fprintf(out_file, "tdi_receive" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "len=%d" PARAM_SEP "flags=0x%x" PARAM_SEP "data=%s",
				event->tdi_receive.file_object,
				event->tdi_receive.length,
				event->tdi_receive.flags,
				print_binary(event->tdi_receive.data, event->tdi_receive.length));
		break;
	case ET_TDI_RECEIVE_DATAGRAM:
		out_fprintf(out_file, "tdi_receive_datagram" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "len=%d" PARAM_SEP "flags=0x%x" PARAM_SEP
				"reqaddr=%s" PARAM_SEP "retaddr=%s" PARAM_SEP "data=%s",
				event->tdi_receive_datagram.file_object,
				event->tdi_receive_datagram.length,
				event->tdi_receive_datagram.flags,
				print_tdi_transport_address(&event->tdi_receive_datagram.request_addr),
				print_tdi_transport_address(&event->tdi_receive_datagram.return_addr),
				print_binary(event->tdi_receive_datagram.data, event->tdi_receive_datagram.length));
		break;
	case ET_TDI_SEND:
		out_fprintf(out_file, "tdi_send" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "len=%d" PARAM_SEP "flags=0x%x" PARAM_SEP "data=%s",
				event->tdi_send.file_object,
				event->tdi_send.length,
				event->tdi_send.flags,
				print_binary(event->tdi_send.data, event->tdi_send.length));
		break;
	case ET_TDI_SEND_DATAGRAM:
		out_fprintf(out_file, "tdi_send_datagram" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "len=%d" PARAM_SEP "addr=%s" PARAM_SEP "data=%s",
				event->tdi_send_datagram.file_object,
				event->tdi_send_datagram.length,
				print_tdi_transport_address(&event->tdi_send_datagram.addr),
				print_binary(event->tdi_send_datagram.data, event->tdi_send_datagram.length));
		break;
	case ET_TDI_SET_EVENT_HANDLER:
		out_fprintf(out_file, "tdi_set_event_handler" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "type=%d" PARAM_SEP "handler=0x%x" PARAM_SEP "context=0x%x",
				event->tdi_set_event_handler.file_object,
				event->tdi_set_event_handler.type,
				event->tdi_set_event_handler.handler,
				event->tdi_set_event_handler.context);
		break;
	case ET_TDI_EVENT_CONNECT:
		out_fprintf(out_file, "tdi_event_connect" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "addr=%s" PARAM_SEP "udl=%d" PARAM_SEP "ol=%d",
				event->tdi_event_connect.file_object,
				print_tdi_transport_address(&event->tdi_event_connect.addr),
				event->tdi_event_connect.user_data_length,
				event->tdi_event_connect.options_length);
		break;
	case ET_TDI_EVENT_DISCONNECT:
		out_fprintf(out_file, "tdi_event_disconnect" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "dl=%d" PARAM_SEP "id=%d" PARAM_SEP "flags=0x%x",
				event->tdi_event_disconnect.file_object,
				event->tdi_event_disconnect.data_length,
				event->tdi_event_disconnect.information_length,
				event->tdi_event_disconnect.flags);
		break;
	case ET_TDI_EVENT_ERROR:
		out_fprintf(out_file, "tdi_event_error" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "cause=0x%x",
				event->tdi_event_error.file_object,
				event->tdi_event_error.cause_status);
		break;
	case ET_TDI_EVENT_RECEIVE:
		out_fprintf(out_file, "tdi_event_receive" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "flags=0x%x" PARAM_SEP
				"bi=%d" PARAM_SEP "ba=%d" PARAM_SEP "bt=%d" PARAM_SEP "data=%s",
				event->tdi_event_receive.file_object,
				event->tdi_event_receive.flags,
				event->tdi_event_receive.bytes_indicated,
				event->tdi_event_receive.bytes_available,
				event->tdi_event_receive.bytes_taken,
				print_binary(event->tdi_event_receive.data, event->tdi_event_receive.bytes_indicated));
		break;
	case ET_TDI_EVENT_RECEIVE_DATAGRAM:
		out_fprintf(out_file, "tdi_event_receive_datagram" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "addr=%s" PARAM_SEP "ol=%d" PARAM_SEP "flags=0x%x" PARAM_SEP
				"bi=%d" PARAM_SEP "ba=%d" PARAM_SEP "bt=%d" PARAM_SEP "data=%s",
				event->tdi_event_receive_datagram.file_object,
				print_tdi_transport_address(&event->tdi_event_receive_datagram.addr),
				event->tdi_event_receive_datagram.options_length,
				event->tdi_event_receive_datagram.flags,
				event->tdi_event_receive_datagram.bytes_indicated,
				event->tdi_event_receive_datagram.bytes_available,
				event->tdi_event_receive_datagram.bytes_taken,
				print_binary(event->tdi_event_receive_datagram.data, event->tdi_event_receive_datagram.bytes_indicated));
		break;
	case ET_TDI_EVENT_RECEIVE_EXPEDITED:
		out_fprintf(out_file, "tdi_event_receive_expedited" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "flags=0x%x" PARAM_SEP
				"bi=%d" PARAM_SEP "ba=%d" PARAM_SEP "bt=%d" PARAM_SEP "data=%s",
				event->tdi_event_receive.file_object,
				event->tdi_event_receive.flags,
				event->tdi_event_receive.bytes_indicated,
				event->tdi_event_receive.bytes_available,
				event->tdi_event_receive.bytes_taken,
				print_binary(event->tdi_event_receive.data, event->tdi_event_receive.bytes_indicated));
		break;
	case ET_TDI_EVENT_SEND_POSSIBLE:
		out_fprintf(out_file, "tdi_event_send_possible" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "ba=%d",
				event->tdi_event_send_possible.file_object,
				event->tdi_event_send_possible.bytes_available);
		break;
	case ET_TDI_EVENT_CHAINED_RECEIVE:
		out_fprintf(out_file, "tdi_event_chained_receive" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "flags=0x%x" PARAM_SEP "len=%d" PARAM_SEP "data=%s",
				event->tdi_event_chained_receive.file_object,
				event->tdi_event_chained_receive.flags,
				event->tdi_event_chained_receive.length,
				print_binary(event->tdi_event_chained_receive.data, event->tdi_event_chained_receive.length));
		break;
	case ET_TDI_EVENT_CHAINED_RECEIVE_DATAGRAM:
		out_fprintf(out_file, "tdi_event_chained_receive_datagram" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "addr=%s" PARAM_SEP "ol=%d" PARAM_SEP
				"flags=0x%x" PARAM_SEP, "len=%d" PARAM_SEP "data=%s",
				event->tdi_event_chained_receive_datagram.file_object,
				print_tdi_transport_address(&event->tdi_event_chained_receive_datagram.addr),
				event->tdi_event_chained_receive_datagram.options_length,
				event->tdi_event_chained_receive_datagram.flags,
				event->tdi_event_chained_receive_datagram.length,
				print_binary(event->tdi_event_chained_receive_datagram.data, event->tdi_event_chained_receive_datagram.length));
		break;
	case ET_TDI_EVENT_CHAINED_RECEIVE_EXPEDITED:
		out_fprintf(out_file, "tdi_event_chained_receive_expedited" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "flags=0x%x" PARAM_SEP "len=%d" PARAM_SEP "data=%s",
				event->tdi_event_chained_receive.file_object,
				event->tdi_event_chained_receive.flags,
				event->tdi_event_chained_receive.length,
				print_binary(event->tdi_event_chained_receive.data, event->tdi_event_chained_receive.length));
		break;
	case ET_TDI_EVENT_ERROR_EX:
		out_fprintf(out_file, "tdi_event_error_ex" FIELD_SEP FIELD_SEP
				"f=0x%x" PARAM_SEP "cause=0x%x",
				event->tdi_event_error_ex.file_object,
				event->tdi_event_error_ex.cause_status);
		break;
	default:
		out_fprintf(out_file, "unknown-%d" FIELD_SEP FIELD_SEP, event->type);
	}

#ifdef TRACE_STACK
	out_fprintf(out_file, FIELD_SEP);
	if (event->stack_n != 0) {
		int i;
		out_fprintf(out_file, "%08x", event->stack_ret[0]);
		for (i = 1; i < event->stack_n; i ++)
			out_fprintf(out_file, " %08x", event->stack_ret[i]);
	}
#endif

	out_fprintf(out_file, "\n");

	if (event->serial % 256 == 0) {
		while (deleting_head != NULL) {
			struct proc_info *curr = deleting_head;

			if (event->serial - curr->deleting_age < 1024)
				break;

			deleting_head = curr->deleting_next;
			if (deleting_head == NULL)
				deleting_tail = NULL;

			phash_remove(curr->pid);
		}
	}
}

static DWORD service_init (void)
{
	DWORD retval;
	SYSTEMTIME local_time;
	char out_file_name[100];

	if(!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
		retval = GetLastError();
		OutputDebugString("SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS) failed.\n");
		return retval;
	}
	if(!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)) {
		retval = GetLastError();
		OutputDebugString("SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) failed.\n");
		return retval;
	}

	driver_file = CreateFile("\\\\.\\resmon",
			GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver_file == INVALID_HANDLE_VALUE) {
		retval = GetLastError();
		OutputDebugString("CreateFile(\"\\\\.\\resmon\") failed.\n");
		return retval;
	}

	ready_event = OpenEvent(SYNCHRONIZE, FALSE, "Global\\resmonready");
	if (ready_event == NULL) {
		retval = GetLastError();
		OutputDebugString("OpenEvent(\"Global\\resmonready\") failed.\n");
		return retval;
	}

	section = OpenFileMapping(FILE_MAP_READ, FALSE, "Global\\resmoneb");
	if (section == NULL) {
		retval = GetLastError();
		OutputDebugString("OpenFileMapping(\"Global\\resmoneb\") failed.\n");
		return retval;
	}

	event_buffer = (struct event_buffer *)MapViewOfFile(section, FILE_MAP_READ, 0, 0, sizeof(struct event_buffer));
	if (event_buffer == NULL) {
		retval = GetLastError();
		OutputDebugString("MapViewOfFile() failed.\n");
		return retval;
	}

	GetLocalTime(&local_time);
	if (config_service_enable_gzip) {
		out_fprintf = gzprintf;
		sprintf_s(out_file_name, sizeof(out_file_name), "C:\\resmon.%04d%02d%02d-%02d%02d%02d.log.gz",
				local_time.wYear, local_time.wMonth, local_time.wDay,
				local_time.wHour, local_time.wMinute, local_time.wSecond);
		out_file = (FILE *)gzopen(out_file_name, "wb");
	} else {
		out_fprintf = fprintf;
		sprintf_s(out_file_name, sizeof(out_file_name), "C:\\resmon.%04d%02d%02d-%02d%02d%02d.log",
				local_time.wYear, local_time.wMonth, local_time.wDay,
				local_time.wHour, local_time.wMinute, local_time.wSecond);
		out_file = fopen(out_file_name, "w");
	}
	if (out_file == NULL) {
		retval = GetLastError(); // FIXME: how to translate errno to win32 LastError? needed?
		OutputDebugString("Cannot open \"C:\\resmon.yyyymmdd-hhmmss.log\" for writing.\n");
		return retval;
	}

	stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (stop_event == NULL) {
		retval = GetLastError();
		OutputDebugString("CreateEvent() failed.\n");
		return retval;
	}

	phash_init();

	return 0;
}

static DWORD service_process (void)
{
	const HANDLE objs[] = {stop_event, ready_event};

	//objs[0] = stop_event;
	//objs[1] = ready_event;

	for (;;) {
		DWORD retval;
		DWORD wait_status;
		int i;

		wait_status = WaitForMultipleObjects(2, objs, FALSE, config_service_wait);
		if (wait_status == WAIT_FAILED) {
			retval = GetLastError();
			OutputDebugString("WaitForMultipleObjects() failed.\n");
			return retval;
		}
		if (wait_status == WAIT_ABANDONED_0) {
			OutputDebugString("WaitForMultipleObjects(): stop_event abandoned.\n");
			return 0;
		}
		if (wait_status == WAIT_ABANDONED_0 + 1) {
			OutputDebugString("WaitForMultipleObjects(): ready_event abandoned.\n");
			return 0;
		}
		if (wait_status == WAIT_OBJECT_0)
			return 0;

		if (!DeviceIoControl(driver_file, (ULONG)IOCTL_REQUEST_SWAP,
					NULL, 0, NULL, 0,
					&i, NULL)) {
			retval = GetLastError();
			OutputDebugString("DeviceIoControl() failed.\n");
			return retval;
		}

		for (i = event_buffer->reading_head; i != -1; i = event_buffer->pool[i].next) {
			process_event(&event_buffer->pool[i]);
		}
	}

	return 0;
}

static DWORD service_fini (void)
{
	if (stop_event != NULL) {
		CloseHandle(stop_event);
		stop_event = NULL;
	}
	if (out_file != NULL) {
		if (config_service_enable_gzip)
			gzclose((gzFile)out_file);
		else
			fclose(out_file);
		out_file = NULL;
	}
	if (ready_event != NULL) {
		CloseHandle(ready_event);
		ready_event = NULL;
	}
	if (event_buffer != NULL) {
		UnmapViewOfFile(event_buffer);
		event_buffer = NULL;
	}
	if (section != NULL) {
		CloseHandle(section);
		section = NULL;
	}
	if (driver_file != NULL) {
		CloseHandle(driver_file);
		driver_file = NULL;
	}
	return 0;
}

static DWORD WINAPI service_handler (DWORD control_code, DWORD event_type, void *data, void *context)
{
	switch (control_code) {
	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		if (!SetEvent(stop_event)) {
			OutputDebugString("SetEvent(stop_event) failed\n");
			// FIXME: what to return?
		}
		return NO_ERROR;
	default:
		return ERROR_CALL_NOT_IMPLEMENTED;
	}
}

static void WINAPI service_main (DWORD argc, char *argv[])
{
	SERVICE_STATUS_HANDLE status_handle;
	SERVICE_STATUS status;
	DWORD error;

	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	//status.dwCurrentState = SERVICE_START_PENDING;
	//status.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
	status.dwWin32ExitCode = NO_ERROR;
	status.dwServiceSpecificExitCode = NO_ERROR;
	status.dwCheckPoint = 0;
	status.dwWaitHint = 0;

	status_handle = RegisterServiceCtrlHandlerEx("resmond", service_handler, NULL);
	if (status_handle == NULL) {
		OutputDebugString("RegisterServiceCtrlHandlerEx failed\n");
		return;
	}

	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = 0;
	SetServiceStatus(status_handle, &status);

	error = service_init();
	if (error) {
		status.dwCurrentState = SERVICE_STOPPED;
		status.dwControlsAccepted = 0;
		status.dwWin32ExitCode = error;
		SetServiceStatus(status_handle, &status);
		return;
	}

	status.dwCurrentState = SERVICE_RUNNING;
	status.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
	SetServiceStatus(status_handle, &status);

	error = service_process();
	if (error) {
		status.dwCurrentState = SERVICE_STOPPED;
		status.dwControlsAccepted = 0;
		status.dwWin32ExitCode = error;
		SetServiceStatus(status_handle, &status);
		return;
	}

	status.dwCurrentState = SERVICE_STOP_PENDING;
	status.dwControlsAccepted = 0;
	SetServiceStatus(status_handle, &status);

	status.dwCurrentState = SERVICE_STOPPED;
	status.dwControlsAccepted = 0;
	status.dwWin32ExitCode = service_fini();
	SetServiceStatus(status_handle, &status);
}

static int run_service (void)
{
	const SERVICE_TABLE_ENTRY entries[] = {
		{"resmond", service_main},
		{NULL, NULL}
	};
	if (!StartServiceCtrlDispatcher(entries)) {
		OutputDebugString("StartServiceCtrlDispatcher failed\n");
		return 1;
	}
	return 0;
}

static int run_console (void)
{
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

	if (config_console_enable_gzip) {
		out_fprintf = fprintf;
		out_file = (FILE *)gzdopen(1, "wb");
		if (out_file == NULL) {
			DWORD retval = GetLastError(); // FIXME: how to translate errno to win32 LastError? needed?
			OutputDebugString("Cannot open \"C:\\resmon.log\" for writing.\n");
			return retval;
		}
	} else {
		out_fprintf = fprintf;
		out_file = stdout;
	}

	phash_init();

	for (;;) {
		DWORD wait_status;
		int i;

		// wait for at most 1 sec
		wait_status = WaitForSingleObject(ready_event, config_console_wait);
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

		for (i = event_buffer->reading_head; i != -1; i = event_buffer->pool[i].next) {
			process_event(&event_buffer->pool[i]);
		}
	}

	if (ready_event != NULL) {
		CloseHandle(ready_event);
		ready_event = NULL;
	}
	if (event_buffer != NULL) {
		UnmapViewOfFile(event_buffer);
		event_buffer = NULL;
	}
	if (section != NULL) {
		CloseHandle(section);
		section = NULL;
	}
	if (driver_file != NULL) {
		CloseHandle(driver_file);
		driver_file = NULL;
	}

	return 0;
}

static int install (void)
{
	SC_HANDLE scm, service;
	char cmd[256];
	int path_length;

	path_length = GetModuleFileName(NULL, cmd + 1, sizeof(cmd) - 10);
	if (path_length == 0) {
		printf("GetModuleFileName() failed. err=%d\n", GetLastError());
		return 1;
	}
	cmd[0] = '\"';
	memcpy(cmd + 1 + path_length, "\" /s", 5);

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (scm == NULL) {
		printf("OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE) failed. err=%d\n", GetLastError());
		return 1;
	}

	service = CreateService(scm,
			"resmond",
			"ResMon Daemon",
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			cmd,
			NULL,
			NULL,
			"resmonk\0\0",
			NULL,
			NULL);
	if (service == NULL) {
		printf("CreateService() failed. err=%d\n", GetLastError());
		CloseServiceHandle(scm);
		return 1;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(scm);

	return 0;
}

static int uninstall (void)
{
	SC_HANDLE scm, service;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (scm == NULL) {
		printf("OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE) failed. err=%d\n", GetLastError());
		return 1;
	}

	service = OpenService(scm, "resmond", DELETE);
	if (service == NULL) {
		printf("OpenService() failed. err=%d\n", GetLastError());
		CloseServiceHandle(scm);
		return 1;
	}

	if (!DeleteService(service)) {
		printf("DeleteService() failed. err=%d\n", GetLastError());
		CloseServiceHandle(service);
		CloseServiceHandle(scm);
		return 1;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(scm);
	return 0;
}

static void help (void)
{
	printf("usage:\n");
	printf("  resmond.exe /h        : display this help\n");
	printf("  resmond.exe /i        : install service\n");
	printf("  resmond.exe /u        : uninstall service\n");
	printf("  resmond.exe /c        : run as console process. print to stdout\n");
	printf("  resmond.exe /s        : run as service. do not invoke directly\n");
}

int main (int argc, char *argv[])
{
	if (argc == 2 && (strcmp(argv[1], "/h") == 0 || strcmp(argv[1], "-h") == 0)) {
		help();
		return 0;
	}
	if (argc == 2 && (strcmp(argv[1], "/i") == 0 || strcmp(argv[1], "-i") == 0))
		return install();
	if (argc == 2 && (strcmp(argv[1], "/u") == 0 || strcmp(argv[1], "-u") == 0))
		return uninstall();
	if (argc == 2 && (strcmp(argv[1], "/c") == 0 || strcmp(argv[1], "-c") == 0))
		return run_console();
	if (argc == 2 && (strcmp(argv[1], "/s") == 0 || strcmp(argv[1], "-s") == 0))
		return run_service();

	help();
	return 1;
}
