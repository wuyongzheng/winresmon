#include <ntddk.h>
#include "resmonk.h"

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

static const int num_Close = 25;
static NTSTATUS (*stock_Close) (HANDLE Handle);

static const int num_CreateKey = 41;
static NTSTATUS (*stock_CreateKey) (PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class OPTIONAL, ULONG CreateOptions, PULONG Disposition OPTIONAL);
static NTSTATUS resmon_CreateKey   (PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class OPTIONAL, ULONG CreateOptions, PULONG Disposition OPTIONAL)
{
	if (ObjectAttributes != NULL &&
			ObjectAttributes->ObjectName != NULL &&
			ObjectAttributes->ObjectName->Buffer != NULL) {
		DbgPrint("NtCreateKey %u \"%S\"\n", PsGetCurrentProcessId(), ObjectAttributes->ObjectName->Buffer);
	} else {
		DbgPrint("NtCreateKey %u null\n", PsGetCurrentProcessId());
	}
	return (*stock_CreateKey)(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
}


static const int num_DeleteKey = 63;
static NTSTATUS (*stock_DeleteKey) (HANDLE KeyHandle);

static const int num_DeleteValueKey = 65;
static NTSTATUS (*stock_DeleteValueKey) (HANDLE KeyHandle, PUNICODE_STRING ValueName);

static const int num_EnumerateKey = 71;
static NTSTATUS (*stock_EnumerateKey) (HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);

static const int num_EnumerateValueKey = 73;
static NTSTATUS (*stock_EnumerateValueKey) (HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

static const int num_FlushKey = 79;
static NTSTATUS (*stock_FlushKey) (HANDLE KeyHandle);

static const int num_OpenKey = 119;
static NTSTATUS (*stock_OpenKey) (PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
static NTSTATUS resmon_OpenKey   (PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	if (ObjectAttributes != NULL &&
			ObjectAttributes->ObjectName != NULL &&
			ObjectAttributes->ObjectName->Buffer != NULL)
		DbgPrint("NtOpenKey %u \"%S\"\n", PsGetCurrentProcessId(), ObjectAttributes->ObjectName->Buffer);
	else
		DbgPrint("NtCreateKey %u null\n", PsGetCurrentProcessId());
	return (*stock_OpenKey)(KeyHandle, DesiredAccess, ObjectAttributes);
}

static const int num_QueryKey = 160;
static NTSTATUS (*stock_QueryKey) (HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);

static const int num_QueryValueKey = 177;
static NTSTATUS (*stock_QueryValueKey) (HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

static const int num_SetValueKey = 247;
static NTSTATUS (*stock_SetValueKey) (HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex OPTIONAL, ULONG Type, PVOID Data, ULONG DataSize);

NTSTATUS reg_init (void)
{
	void **entries = (void **)KeServiceDescriptorTable->Base;

	_asm
	{
		CLI                    //dissable interrupt
		MOV    EAX, CR0        //move CR0 register into EAX
		AND    EAX, NOT 10000H //disable WP bit
		MOV    CR0, EAX        //write register back
	}

	stock_CreateKey = entries[num_CreateKey];
	entries[num_CreateKey] = resmon_CreateKey;
	stock_OpenKey = entries[num_OpenKey];
	entries[num_OpenKey] = resmon_OpenKey;

	_asm
	{
		MOV    EAX, CR0        //move CR0 register into EAX
		OR     EAX, 10000H     //enable WP bit
		MOV    CR0, EAX        //write register back
		STI                    //enable interrupt
	}

	return STATUS_SUCCESS;
}

void reg_fini (void)
{
	void **entries = (void **)KeServiceDescriptorTable->Base;

	_asm
	{
		CLI                    //dissable interrupt
		MOV    EAX, CR0        //move CR0 register into EAX
		AND    EAX, NOT 10000H //disable WP bit
		MOV    CR0, EAX        //write register back
	}

	entries[num_CreateKey] = stock_CreateKey;
	entries[num_OpenKey] = stock_OpenKey;

	_asm
	{
		MOV    EAX, CR0        //move CR0 register into EAX
		OR     EAX, 10000H     //enable WP bit
		MOV    CR0, EAX        //write register back
		STI                    //enable interrupt
	}
}
