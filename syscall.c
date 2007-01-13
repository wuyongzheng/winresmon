#include <ntddk.h>
#include "resmonk.h"

/*
thanks to:
Paula Tomlinson
http://www.ddj.com/dept/windows/184416453
http://www.ddj.com/showArticle.jhtml?documentID=wdj9702h&pgno=7
Mark Russinovich and Bryce Cogswell
http://www.ddj.com/184410109
*/

/* list of registry call:
 * NtCreateKey
 * NtDeleteKey
 * NtDeleteValueKey
 * NtEnumerateKey
 * NtEnumerateValueKey
 * NtFlushKey
 * NtInitializeRegistry
 * NtNotifyChangeKey
 * NtNotifyChangeMultipleKeys
 * NtOpenKey
 * NtQueryKey
 * NtQueryValueKey
 * NtQueryMultipleValueKey
 * NtRestoreKey
 * NtSaveKey
 * NtSaveKeyEx
 * NtSaveMergedKeys
 * NtSetValueKey
 * NtLoadKey
 * NtLoadKey2
 * NtLoadKeyEx
 * NtUnloadKey
 * NtUnloadKey2
 * NtUnloadKeyEx
 * NtSetInformationKey
 * NtReplaceKey
 * NtRenameKey
 * NtQueryOpenSubKeys
 * NtQueryOpenSubKeysEx
 */

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;
	PULONG Count;
	ULONG Limit;
#if defined(_IA64_)
	LONG TableBaseGpOffset;
#endif
	PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

static void *stock_NtCreateKey;
static NTSTATUS NTAPI my_NtCreateKey (
		OUT PHANDLE KeyHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG TitleIndex,
		PUNICODE_STRING Class,
		ULONG CreateOptions,
		PULONG Disposition)
{
	if (ObjectAttributes != NULL &&
			ObjectAttributes->ObjectName != NULL &&
			ObjectAttributes->ObjectName->Buffer != NULL) {
		DbgPrint("NtCreateKey %u \"%S\"\n", PsGetCurrentProcessId(), ObjectAttributes->ObjectName->Buffer);
	} else {
		DbgPrint("NtCreateKey %u null\n", PsGetCurrentProcessId());
	}
	return (*(NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG))stock_NtCreateKey)(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
}

static void *stock_NtOpenKey;
static NTSTATUS NTAPI my_NtOpenKey (
		PHANDLE KeyHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes)
{
	if (ObjectAttributes != NULL &&
			ObjectAttributes->ObjectName != NULL &&
			ObjectAttributes->ObjectName->Buffer != NULL)
		DbgPrint("NtOpenKey %u \"%S\"\n", PsGetCurrentProcessId(), ObjectAttributes->ObjectName->Buffer);
	else
		DbgPrint("NtCreateKey %u null\n", PsGetCurrentProcessId());
	return (*(NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))stock_NtOpenKey)(KeyHandle, DesiredAccess, ObjectAttributes);
}

static void *stock_NtCreateFile;
static NTSTATUS NTAPI my_NtCreateFile(
		PHANDLE FileHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock,
		PLARGE_INTEGER AllocationSize,
		ULONG FileAttributes,
		ULONG ShareAccess,
		ULONG CreateDisposition,
		ULONG CreateOptions,
		PVOID EaBuffer,
		ULONG EaLength)
{
	if (ObjectAttributes != NULL &&
			ObjectAttributes->ObjectName != NULL &&
			ObjectAttributes->ObjectName->Buffer != NULL) {
		DbgPrint("NtCreateFile %u \"%S\"\n", PsGetCurrentProcessId(), ObjectAttributes->ObjectName->Buffer);
	} else {
		DbgPrint("NtCreateFile %u null\n", PsGetCurrentProcessId());
	}
	return (*(NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG))stock_NtCreateFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

static void *stock_NtCreateNamedPipeFile;
static NTSTATUS NTAPI my_NtCreateNamedPipeFile(
		PHANDLE NamedPipeFileHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG ShareAccess,
		ULONG CreateDisposition,
		ULONG CreateOptions,
		BOOLEAN WriteModeMessage,
		BOOLEAN ReadModeMessage,
		BOOLEAN NonBlocking,
		ULONG MaxInstances,
		ULONG InBufferSize,
		ULONG OutBufferSize,
		PLARGE_INTEGER DefaultTimeOut)
{
	if (ObjectAttributes != NULL &&
			ObjectAttributes->ObjectName != NULL &&
			ObjectAttributes->ObjectName->Buffer != NULL) {
		DbgPrint("NtCreateNamedPipeFile %u \"%S\"\n", PsGetCurrentProcessId(), ObjectAttributes->ObjectName->Buffer);
	} else {
		DbgPrint("NtCreateNamedPipeFile %u null\n", PsGetCurrentProcessId());
	}
	return (*(NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, BOOLEAN, BOOLEAN, BOOLEAN, ULONG, ULONG, ULONG, PLARGE_INTEGER))stock_NtCreateNamedPipeFile)(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, WriteModeMessage, ReadModeMessage, NonBlocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeOut);
}

NTSTATUS syscall_init (void)
{
	void **entries = (void **)KeServiceDescriptorTable->Base;

	return STATUS_SUCCESS;

	_asm
	{
		CLI                    //dissable interrupt
		MOV    EAX, CR0        //move CR0 register into EAX
		AND    EAX, NOT 10000H //disable WP bit
		MOV    CR0, EAX        //write register back
	}

//	stock_NtCreateKey = entries[0x029];
//	entries[0x029] = my_NtCreateKey;
//	stock_NtOpenKey = entries[0x077];
//	entries[0x077] = my_NtOpenKey;
//	stock_NtCreateFile = entries[0x025];
//	entries[0x025] = my_NtCreateFile;
	stock_NtCreateNamedPipeFile = entries[0x02c];
	entries[0x02c] = my_NtCreateNamedPipeFile;

	_asm
	{
		MOV    EAX, CR0        //move CR0 register into EAX
		OR     EAX, 10000H     //enable WP bit
		MOV    CR0, EAX        //write register back
		STI                    //enable interrupt
	}

	return STATUS_SUCCESS;
}

void syscall_fini (void)
{
	void **entries = (void **)KeServiceDescriptorTable->Base;

	return;

	_asm
	{
		CLI                    //dissable interrupt
		MOV    EAX, CR0        //move CR0 register into EAX
		AND    EAX, NOT 10000H //disable WP bit
		MOV    CR0, EAX        //write register back
	}

//	entries[0x029] = stock_NtCreateKey;
//	entries[0x077] = stock_NtOpenKey;
//	entries[0x025] = stock_NtCreateFile;
	entries[0x02c] = stock_NtCreateNamedPipeFile;

	_asm
	{
		MOV    EAX, CR0        //move CR0 register into EAX
		OR     EAX, 10000H     //enable WP bit
		MOV    CR0, EAX        //write register back
		STI                    //enable interrupt
	}
}
