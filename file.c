#include <fltkernel.h>
#include "resmonk.h"

static PFLT_FILTER filter = NULL;

/* The original path before FileRenameInformation.
 * Assume renaming is performed infrequently and no two process call rename at the same time.
 * If there is race condition, too bad, we get junk */
static int saved_original_path_length;
static short saved_original_path[MAX_PATH_SIZE]; // always '\0' terminated

static FLT_PREOP_CALLBACK_STATUS on_pre_close (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID *context)
{
	FLT_FILE_NAME_INFORMATION *name_info;
	struct event *event;

	// the condition (data->RequestorMode == KernelMode) is removed because it's always false.
	if (KeGetCurrentIrql() > APC_LEVEL || fltobj->FileObject == NULL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if ((unsigned long)PsGetCurrentProcessId() <= 4 || (unsigned long)PsGetCurrentProcessId() == daemon_pid)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	name_info = NULL;
	if(FltGetFileNameInformation(data,
				FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
				&name_info) != STATUS_SUCCESS) {
		//DbgPrint("resmon+on_pre_close(%u): FltGetFileNameInformation failed: %x\n", data->Iopb->MajorFunction, retval);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	event = event_buffer_start_add();
	if (event != NULL) {
		event->type = ET_FILE_CLOSE;
		event->status = 0;
		event->path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
		RtlCopyMemory(event->path, name_info->Name.Buffer, event->path_length * 2);
		event->path[event->path_length] = 0;
		event_buffer_finish_add(event);
	}

	FltReleaseFileNameInformation(name_info);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS on_pre_set_info (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID *context)
{
	FLT_FILE_NAME_INFORMATION *name_info;

	if (data->RequestorMode == KernelMode || KeGetCurrentIrql() > APC_LEVEL || fltobj->FileObject == NULL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if ((unsigned long)PsGetCurrentProcessId() <= 4 || (unsigned long)PsGetCurrentProcessId() == daemon_pid)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformation)
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;

	name_info = NULL;
	if (FltGetFileNameInformation(data,
				FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
				&name_info) == STATUS_SUCCESS) {
		saved_original_path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
		RtlCopyMemory(saved_original_path, name_info->Name.Buffer, saved_original_path_length * 2);
		saved_original_path[saved_original_path_length] = 0;
		FltReleaseFileNameInformation(name_info);
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS on_post_op (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID context, FLT_POST_OPERATION_FLAGS flags)
{
	NTSTATUS retval;
	FLT_FILE_NAME_INFORMATION *name_info;
	struct event *event;

	if (data->RequestorMode == KernelMode || KeGetCurrentIrql() > APC_LEVEL || fltobj->FileObject == NULL)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if ((unsigned long)PsGetCurrentProcessId() <= 4 || (unsigned long)PsGetCurrentProcessId() == daemon_pid)
		return FLT_POSTOP_FINISHED_PROCESSING;

	name_info = NULL;
	retval = FltGetFileNameInformation(data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&name_info);
	if (retval != STATUS_SUCCESS) {
		//DbgPrint("resmon+on_post_op(%u): FltGetFileNameInformation failed: %x\n", data->Iopb->MajorFunction, retval);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	event = event_buffer_start_add();
	if (event == NULL) {
		FltReleaseFileNameInformation(name_info);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	switch (data->Iopb->MajorFunction) {
	case IRP_MJ_CREATE:
		event->type = ET_FILE_CREATE;
		event->file_create.desired_access       = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
		event->file_create.share_mode           = data->Iopb->Parameters.Create.ShareAccess;
		event->file_create.attributes           = data->Iopb->Parameters.Create.FileAttributes;
		event->file_create.creation_disposition = data->Iopb->Parameters.Create.Options >> 24;
		event->file_create.create_options       = data->Iopb->Parameters.Create.Options & 0x00ffffff;
		break;
	case IRP_MJ_READ:
		event->type = ET_FILE_READ;
		event->file_rw.offset = data->Iopb->Parameters.Read.ByteOffset;
		event->file_rw.req_length = data->Iopb->Parameters.Read.Length;
		event->file_rw.ret_length = data->IoStatus.Information;
		break;
	case IRP_MJ_WRITE:
		event->type = ET_FILE_WRITE;
		event->file_rw.offset = data->Iopb->Parameters.Write.ByteOffset;
		event->file_rw.req_length = data->Iopb->Parameters.Write.Length;
		event->file_rw.ret_length = data->IoStatus.Information;
		break;
	case IRP_MJ_CREATE_MAILSLOT:
		event->type = ET_FILE_CREATE_MAILSLOT;
		break;
	case IRP_MJ_CREATE_NAMED_PIPE:
		event->type = ET_FILE_CREATE_NAMED_PIPE;
		break;
	case IRP_MJ_QUERY_INFORMATION:
		event->type = ET_FILE_QUERY_INFORMATION;
		if (data->IoStatus.Status == STATUS_SUCCESS || data->IoStatus.Status == STATUS_BUFFER_OVERFLOW) {
			event->file_info.info_type = data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
			event->file_info.info_size = data->Iopb->Parameters.QueryFileInformation.Length <
				sizeof(event->file_info.info_data) ?
				data->Iopb->Parameters.QueryFileInformation.Length :
				sizeof(event->file_info.info_data);
			//NOTE: string inside the info structure is not zero terminated.
			RtlCopyMemory(&event->file_info.info_data,
					data->Iopb->Parameters.QueryFileInformation.InfoBuffer,
					event->file_info.info_size);
		}
		break;
	case IRP_MJ_SET_INFORMATION:
		event->type = ET_FILE_SET_INFORMATION;
		event->file_info.info_type = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
		event->file_info.info_size = data->Iopb->Parameters.SetFileInformation.Length <
			sizeof(event->file_info.info_data) ?
			data->Iopb->Parameters.SetFileInformation.Length :
			sizeof(event->file_info.info_data);
		//NOTE: string inside the info structure is not zero terminated.
		RtlCopyMemory(&event->file_info.info_data,
				data->Iopb->Parameters.SetFileInformation.InfoBuffer,
				event->file_info.info_size);
		break;
	default:
		DbgPrint("resmon: unknown post MajorFunction %d\n", data->Iopb->MajorFunction);
		event_buffer_cancel_add(event);
		event = NULL;
	}

	if (event != NULL) {
		event->status = data->IoStatus.Status;
		if (data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
				data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
			event->path_length = saved_original_path_length;
			RtlCopyMemory(event->path, saved_original_path, (saved_original_path_length + 1) * 2);
		} else {
			event->path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
			RtlCopyMemory(event->path, name_info->Name.Buffer, event->path_length * 2);
			event->path[event->path_length] = 0;
		}
		event_buffer_finish_add(event);
	}

	FltReleaseFileNameInformation(name_info);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS file_start (void)
{
	NTSTATUS retval;
	const static FLT_OPERATION_REGISTRATION callbacks[] = {
//		{IRP_MJ_CLEANUP,                             0, NULL, on_post_op, NULL},
		{IRP_MJ_CLOSE,                               0, on_pre_close, NULL, NULL},
		{IRP_MJ_CREATE,                              0, NULL, on_post_op, NULL},
		{IRP_MJ_CREATE_MAILSLOT,                     0, NULL, on_post_op, NULL},
		{IRP_MJ_CREATE_NAMED_PIPE,                   0, NULL, on_post_op, NULL},
//		{IRP_MJ_DEVICE_CONTROL,                      0, NULL, on_post_op, NULL},
//		{IRP_MJ_DIRECTORY_CONTROL,                   0, NULL, on_post_op, NULL},
//		{IRP_MJ_FILE_SYSTEM_CONTROL,                 0, NULL, on_post_op, NULL},
//		{IRP_MJ_FLUSH_BUFFERS,                       0, NULL, on_post_op, NULL},
//		{IRP_MJ_INTERNAL_DEVICE_CONTROL,             0, NULL, on_post_op, NULL},
//		{IRP_MJ_LOCK_CONTROL,                        0, NULL, on_post_op, NULL},
//		{IRP_MJ_PNP,                                 0, NULL, on_post_op, NULL},
//		{IRP_MJ_QUERY_EA,                            0, NULL, on_post_op, NULL},
		{IRP_MJ_QUERY_INFORMATION,                   0, NULL, on_post_op, NULL},
//		{IRP_MJ_QUERY_QUOTA,                         0, NULL, on_post_op, NULL},
//		{IRP_MJ_QUERY_SECURITY,                      0, NULL, on_post_op, NULL},
//		{IRP_MJ_QUERY_VOLUME_INFORMATION,            0, NULL, on_post_op, NULL},
		{IRP_MJ_READ,                                0, NULL, on_post_op, NULL},
//		{IRP_MJ_SET_EA,                              0, NULL, on_post_op, NULL},
		{IRP_MJ_SET_INFORMATION,                     0, on_pre_set_info, on_post_op, NULL},
//		{IRP_MJ_SET_QUOTA,                           0, NULL, on_post_op, NULL},
//		{IRP_MJ_SET_SECURITY,                        0, NULL, on_post_op, NULL},
//		{IRP_MJ_SET_VOLUME_INFORMATION,              0, NULL, on_post_op, NULL},
//		{IRP_MJ_SHUTDOWN,                            0, on_pre_op, NULL, NULL},
//		{IRP_MJ_SYSTEM_CONTROL,                      0, NULL, on_post_op, NULL},
		{IRP_MJ_WRITE,                               0, NULL, on_post_op, NULL},
//		{IRP_MJ_ACQUIRE_FOR_CC_FLUSH,                0, NULL, on_post_op, NULL},
//		{IRP_MJ_ACQUIRE_FOR_MOD_WRITE,               0, NULL, on_post_op, NULL},
//		{IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, NULL, on_post_op, NULL},
//		{IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,           0, NULL, on_post_op, NULL},
//		{IRP_MJ_MDL_READ,                            0, NULL, on_post_op, NULL},
//		{IRP_MJ_MDL_READ_COMPLETE,                   0, NULL, on_post_op, NULL},
//		{IRP_MJ_MDL_WRITE_COMPLETE,                  0, NULL, on_post_op, NULL},
//		{IRP_MJ_NETWORK_QUERY_OPEN,                  0, NULL, on_post_op, NULL},
//		{IRP_MJ_PREPARE_MDL_WRITE,                   0, NULL, on_post_op, NULL},
//		{IRP_MJ_RELEASE_FOR_CC_FLUSH,                0, NULL, on_post_op, NULL},
//		{IRP_MJ_RELEASE_FOR_MOD_WRITE,               0, NULL, on_post_op, NULL},
//		{IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION, 0, NULL, on_post_op, NULL},
//		{IRP_MJ_VOLUME_DISMOUNT,                     0, NULL, on_post_op, NULL},
//		{IRP_MJ_VOLUME_MOUNT,                        0, NULL, on_post_op, NULL},
		{IRP_MJ_OPERATION_END}
	};

	const static FLT_REGISTRATION reg = {
		sizeof(FLT_REGISTRATION),
		FLT_REGISTRATION_VERSION,
		0,
		NULL,
		callbacks,
		NULL,
		NULL, // we don't want to be unloaded by the manager.
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	retval = FltRegisterFilter(driver_object, &reg, &filter);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("FltRegisterFilter failed: err=0x%8x\n", retval);
		return retval;
	}
	retval = FltStartFiltering(filter);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("FltStartFiltering failed: err=0x%8x\n", retval);
		FltUnregisterFilter(filter);
		filter = NULL;
		return retval;
	}

	return STATUS_SUCCESS;
}

void file_stop (void)
{
	FltUnregisterFilter(filter);
	filter = NULL;
}
