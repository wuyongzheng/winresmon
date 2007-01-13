#include <ntddk.h>
#include "resmonk.h"

static LARGE_INTEGER reg_cookie;

static NTSTATUS reg_callback (void *context, void *type, void *info)
{
	switch ((REG_NOTIFY_CLASS)type) {
	case RegNtPreDeleteKey:
		DbgPrint("RegNtPreDeleteKey\n");
		break;
	case RegNtPreSetValueKey:
		break;
	case RegNtPreDeleteValueKey:
		break;
	case RegNtPreSetInformationKey:
		break;
	case RegNtPreRenameKey:
		break;
	case RegNtPreEnumerateKey:
		break;
	case RegNtPreEnumerateValueKey:
		break;
	case RegNtPreQueryKey:
		break;
	case RegNtPreQueryValueKey:
		break;
	case RegNtPreQueryMultipleValueKey:
		break;
	case RegNtPreCreateKey:
		break;
	case RegNtPostCreateKey:
		break;
	case RegNtPreOpenKey:
		break;
	case RegNtPostOpenKey:
		break;
	case RegNtPreKeyHandleClose:
		break;
	default:
		DbgPrint("unknown REG_NOTIFY_CLASS %d\n", (REG_NOTIFY_CLASS)type);
	}
	return STATUS_SUCCESS;
}

NTSTATUS reg_init (void)
{
	NTSTATUS retval = CmRegisterCallback(reg_callback, NULL, &reg_cookie);
	if (retval != STATUS_SUCCESS) {
		DbgPrint("CmRegisterCallback failed, retval=%d\n", retval);
		return retval;
	}
	return STATUS_SUCCESS;
}

void reg_fini (void)
{
	CmUnRegisterCallback(reg_cookie);
}
