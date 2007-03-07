#include <fltkernel.h>
#include "resmonk.h"

static PFLT_FILTER filter = NULL;

static FLT_PREOP_CALLBACK_STATUS on_pre_op (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID *context)
{
	NTSTATUS retval;
	FLT_FILE_NAME_INFORMATION *name_info;
	struct event *event;

	if (data->RequestorMode == KernelMode || KeGetCurrentIrql() > APC_LEVEL || fltobj->FileObject == NULL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	name_info = NULL;
	retval = FltGetFileNameInformation(data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&name_info);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("resmon+on_pre_op(%u): FltGetFileNameInformation failed: %x\n", data->Iopb->MajorFunction, retval);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	event = event_buffer_start_add();
	if (event == NULL) {
		FltReleaseFileNameInformation(name_info);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	switch (data->Iopb->MajorFunction) {
	case IRP_MJ_CLOSE:
		event->type = ET_FILE_CLOSE;
		break;
	default:
		DbgPrint("resmon: unknown pre MajorFunction %d\n", data->Iopb->MajorFunction);
		event_buffer_cancel_add();
		event = NULL;
	}

	if (event != NULL) {
		event->status = 0;
		event->path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
		RtlCopyMemory(event->path, name_info->Name.Buffer, event->path_length * 2);
		event->path[event->path_length] = 0;
		event_buffer_finish_add();
	}

	FltReleaseFileNameInformation(name_info);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS on_post_op (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID context, FLT_POST_OPERATION_FLAGS flags)
{
	NTSTATUS retval;
	FLT_FILE_NAME_INFORMATION *name_info;
	struct event *event;

	if (data->RequestorMode == KernelMode || KeGetCurrentIrql() > APC_LEVEL || fltobj->FileObject == NULL)
		return FLT_POSTOP_FINISHED_PROCESSING;

	name_info = NULL;
	retval = FltGetFileNameInformation(data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&name_info);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("resmon+on_post_op(%u): FltGetFileNameInformation failed: %x\n", data->Iopb->MajorFunction, retval);
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
		event->file_rw.length = data->Iopb->Parameters.Read.Length;
		break;
	case IRP_MJ_WRITE:
		event->type = ET_FILE_WRITE;
		event->file_rw.offset = data->Iopb->Parameters.Write.ByteOffset;
		event->file_rw.length = data->Iopb->Parameters.Write.Length;
		break;
	case IRP_MJ_CREATE_MAILSLOT:
		event->type = ET_FILE_CREATE_MAILSLOT;
		break;
	case IRP_MJ_CREATE_NAMED_PIPE:
		event->type = ET_FILE_CREATE_NAMED_PIPE;
		break;
	case IRP_MJ_QUERY_INFORMATION:
		event->type = ET_FILE_QUERY_INFORMATION;
		switch (data->Iopb->Parameters.QueryFileInformation.FileInformationClass) {
		case FileAllInformation:
			DbgPrint("resmon: FileAllInformation ignored\n");
			event_buffer_cancel_add();
			event = NULL;
			break;
		case FileAttributeTagInformation:
		case FileBasicInformation:
		case FileCompressionInformation:
		case FileEaInformation:
		case FileInternalInformation:
		case FileNameInformation:
		case FileNetworkOpenInformation:
		case FilePositionInformation:
		case FileStandardInformation:
		case FileStreamInformation:
			if (data->IoStatus.Status == STATUS_SUCCESS) {
				// NOTE: unicode string at the end is not sero terminated
				event->file_info.info_type = data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
				event->file_info.info_size = data->Iopb->Parameters.QueryFileInformation.Length < sizeof(event->file_info.info_data) ? data->Iopb->Parameters.QueryFileInformation.Length : sizeof(event->file_info.info_data);
				RtlCopyMemory(&event->file_info.info_data,
						data->Iopb->Parameters.QueryFileInformation.InfoBuffer,
						event->file_info.info_size);
			}
			break;
		default:
			DbgPrint("resmon: unknown FileInformationClass %d in IRP_MJ_QUERY_INFORMATION\n",
					data->Iopb->Parameters.QueryFileInformation.FileInformationClass);
			event_buffer_cancel_add();
			event = NULL;
		}
		break;
	case IRP_MJ_SET_INFORMATION:
		event->type = ET_FILE_SET_INFORMATION;
		switch (data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
		case FileAllocationInformation:
		case FileBasicInformation:
		case FileDispositionInformation:
		case FileEndOfFileInformation:
		case FileLinkInformation:
		case FilePositionInformation:
		case FileRenameInformation:
		case FileValidDataLengthInformation:
			// NOTE: unicode string at the end is not sero terminated
			event->file_info.info_type = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
			event->file_info.info_size = data->Iopb->Parameters.SetFileInformation.Length < sizeof(event->file_info.info_data) ? data->Iopb->Parameters.SetFileInformation.Length : sizeof(event->file_info.info_data);
			RtlCopyMemory(&event->file_info.info_data,
					data->Iopb->Parameters.SetFileInformation.InfoBuffer,
					event->file_info.info_size);
			break;
		default:
			DbgPrint("resmon: unknown FileInformationClass %d in IRP_MJ_SET_INFORMATION\n",
					data->Iopb->Parameters.SetFileInformation.FileInformationClass);
			event_buffer_cancel_add();
			event = NULL;
		}
		break;
	default:
		DbgPrint("resmon: unknown post MajorFunction %d\n", data->Iopb->MajorFunction);
		event_buffer_cancel_add();
		event = NULL;
	}

	if (event != NULL) {
		event->status = data->IoStatus.Status;
		event->path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
		RtlCopyMemory(event->path, name_info->Name.Buffer, event->path_length * 2);
		event->path[event->path_length] = 0;
		event_buffer_finish_add();
	}

	FltReleaseFileNameInformation(name_info);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS file_init (void)
{
	NTSTATUS retval;
	const FLT_OPERATION_REGISTRATION callbacks[] = {
//		{IRP_MJ_CLEANUP,                             0, NULL, on_post_op, NULL},
		{IRP_MJ_CLOSE,                               0, on_pre_op, NULL, NULL},
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
		{IRP_MJ_SET_INFORMATION,                     0, NULL, on_post_op, NULL},
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

	const FLT_REGISTRATION reg = {
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

void file_fini (void)
{
	FltUnregisterFilter(filter);
	filter = NULL;
}
