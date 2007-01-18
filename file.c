#include <fltkernel.h>
#include "resmonk.h"

static PFLT_FILTER filter = NULL;

static FLT_PREOP_CALLBACK_STATUS on_pre_close (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID *context)
{
	NTSTATUS retval;
	FLT_FILE_NAME_INFORMATION *name_info = NULL;
	struct event *event;
	int path_length;

	retval = FltGetFileNameInformation(data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&name_info);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("resmon: FltGetFileNameInformation failed: %x\n", retval);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	event = event_buffer_start_add();
	if (event == NULL) {
		FltReleaseFileNameInformation(name_info);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	event->type = ET_FILE_CLOSE;
	event->status = 0;
	path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
	RtlCopyMemory(event->path, name_info->Name.Buffer, path_length * 2);
	event->path[path_length] = 0;
	event_buffer_finish_add();

	FltReleaseFileNameInformation(name_info);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS on_post_create (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID context, FLT_POST_OPERATION_FLAGS flags)
{
	NTSTATUS retval;
	FLT_FILE_NAME_INFORMATION *name_info = NULL;
	struct event *event;
	int path_length;

	retval = FltGetFileNameInformation(data,
			FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&name_info);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("resmon: FltGetFileNameInformation failed: %x\n", retval);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	event = event_buffer_start_add();
	if (event == NULL) {
		FltReleaseFileNameInformation(name_info);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	event->type = ET_FILE_CREATE;
	event->status = data->IoStatus.Status;
	event->file_create.desired_access       = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	event->file_create.share_mode           = data->Iopb->Parameters.Create.ShareAccess;
	event->file_create.attributes           = data->Iopb->Parameters.Create.FileAttributes;
	event->file_create.creation_disposition = data->Iopb->Parameters.Create.Options >> 24;
	event->file_create.create_options       = data->Iopb->Parameters.Create.Options & 0x00ffffff;
	path_length = MAX_PATH_SIZE - 1 < name_info->Name.Length / 2 ? MAX_PATH_SIZE - 1 : name_info->Name.Length / 2;
	RtlCopyMemory(event->path, name_info->Name.Buffer, path_length * 2);
	event->path[path_length] = 0;
	event_buffer_finish_add();

	FltReleaseFileNameInformation(name_info);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS on_post_read (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID context, FLT_POST_OPERATION_FLAGS flags)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS on_post_write (PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltobj, PVOID context, FLT_POST_OPERATION_FLAGS flags)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS file_init (void)
{
	NTSTATUS retval;
	const FLT_OPERATION_REGISTRATION callbacks[] = {
//		{IRP_MJ_CLEANUP,                             0, NULL, on_post_cleanup, NULL},
		{IRP_MJ_CLOSE,                               0, on_pre_close, NULL, NULL},
		{IRP_MJ_CREATE,                              0, NULL, on_post_create, NULL},
//		{IRP_MJ_CREATE_MAILSLOT,                     0, NULL, on_post_create_mailslot, NULL},
//		{IRP_MJ_CREATE_NAMED_PIPE,                   0, NULL, on_post_create_named_pipe, NULL},
//		{IRP_MJ_DEVICE_CONTROL,                      0, NULL, on_post_device_control, NULL},
//		{IRP_MJ_DIRECTORY_CONTROL,                   0, NULL, on_post_directory_control, NULL},
//		{IRP_MJ_FILE_SYSTEM_CONTROL,                 0, NULL, on_post_file_system_control, NULL},
//		{IRP_MJ_FLUSH_BUFFERS,                       0, NULL, on_post_flush_buffers, NULL},
//		{IRP_MJ_INTERNAL_DEVICE_CONTROL,             0, NULL, on_post_internal_device_control, NULL},
//		{IRP_MJ_LOCK_CONTROL,                        0, NULL, on_post_lock_control, NULL},
//		{IRP_MJ_PNP,                                 0, NULL, on_post_pnp, NULL},
//		{IRP_MJ_QUERY_EA,                            0, NULL, on_post_query_ea, NULL},
//		{IRP_MJ_QUERY_INFORMATION,                   0, NULL, on_post_query_information, NULL},
//		{IRP_MJ_QUERY_QUOTA,                         0, NULL, on_post_query_quota, NULL},
//		{IRP_MJ_QUERY_SECURITY,                      0, NULL, on_post_query_security, NULL},
//		{IRP_MJ_QUERY_VOLUME_INFORMATION,            0, NULL, on_post_query_volume_information, NULL},
		{IRP_MJ_READ,                                0, NULL, on_post_read, NULL},
//		{IRP_MJ_SET_EA,                              0, NULL, on_post_set_ea, NULL},
//		{IRP_MJ_SET_INFORMATION,                     0, NULL, on_post_set_information, NULL},
//		{IRP_MJ_SET_QUOTA,                           0, NULL, on_post_set_quota, NULL},
//		{IRP_MJ_SET_SECURITY,                        0, NULL, on_post_set_security, NULL},
//		{IRP_MJ_SET_VOLUME_INFORMATION,              0, NULL, on_post_set_volume_information, NULL},
//		{IRP_MJ_SHUTDOWN,                            0, on_pre_shutdown, NULL, NULL},
//		{IRP_MJ_SYSTEM_CONTROL,                      0, NULL, on_post_system_control, NULL},
		{IRP_MJ_WRITE,                               0, NULL, on_post_write, NULL},
//		{IRP_MJ_ACQUIRE_FOR_CC_FLUSH,                0, NULL, on_post_acquire_for_cc_flush, NULL},
//		{IRP_MJ_ACQUIRE_FOR_MOD_WRITE,               0, NULL, on_post_acquire_for_mod_write, NULL},
//		{IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, NULL, on_post_acquire_for_section_synchronization, NULL},
//		{IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,           0, NULL, on_post_fast_io_check_if_possible, NULL},
//		{IRP_MJ_MDL_READ,                            0, NULL, on_post_mdl_read, NULL},
//		{IRP_MJ_MDL_READ_COMPLETE,                   0, NULL, on_post_mdl_read_complete, NULL},
//		{IRP_MJ_MDL_WRITE_COMPLETE,                  0, NULL, on_post_mdl_write_complete, NULL},
//		{IRP_MJ_NETWORK_QUERY_OPEN,                  0, NULL, on_post_network_query_open, NULL},
//		{IRP_MJ_PREPARE_MDL_WRITE,                   0, NULL, on_post_prepare_mdl_write, NULL},
//		{IRP_MJ_RELEASE_FOR_CC_FLUSH,                0, NULL, on_post_release_for_cc_flush, NULL},
//		{IRP_MJ_RELEASE_FOR_MOD_WRITE,               0, NULL, on_post_release_for_mod_write, NULL},
//		{IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION, 0, NULL, on_post_release_for_section_synchronization, NULL},
//		{IRP_MJ_VOLUME_DISMOUNT,                     0, NULL, on_post_volume_dismount, NULL},
//		{IRP_MJ_VOLUME_MOUNT,                        0, NULL, on_post_volume_mount, NULL},
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
