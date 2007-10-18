#include <ntddk.h> 
#include "resmonk.h"

static struct event_buffer *event_buffer = NULL;
static HANDLE event_buffer_section = NULL;
static KSPIN_LOCK event_buffer_lock;
static MDL *event_buffer_mdl = NULL;
static KEVENT *event_buffer_readyevent = NULL;
static HANDLE event_buffer_readyeventhandle = NULL;

struct event *event_buffer_start_add (void)
{
	struct event *event = NULL;
	KLOCK_QUEUE_HANDLE lock_handle;

	KeAcquireInStackQueuedSpinLock(&event_buffer_lock, &lock_handle);
	if (event_buffer->free_count == 0) {
		event_buffer->dropped ++;
	} else {
		event = &event_buffer->pool[event_buffer->free_head];
		event_buffer->free_head = event->next;
		event_buffer->free_count --;
	}
	KeReleaseInStackQueuedSpinLock(&lock_handle);

	if (event == NULL)
		return NULL;

	event->pid = (unsigned long)PsGetCurrentProcessId();
	event->tid = (unsigned long)PsGetCurrentThreadId();

#ifdef TRACE_STACK
	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		int stack_count = 0;
		unsigned int *kstack_base, *user_esp, *user_ebp;

		try {
			// fs:[40h] + 4 is kernel stack base address
			__asm {
				mov eax, fs:[40h]
				mov ebx, [eax+4h]
				mov kstack_base, ebx
			};
			/* initial kernel stack layout
			 * 1-4 ss, esp, eflags, cs
			 * 5-8 ret addr, 0, ebp, ebx
			 * 9-c esi, edi, fs, except list
			 */
			user_esp = (unsigned int *)*(kstack_base - 2);
			ProbeForRead(user_esp, sizeof(unsigned int) * 2, sizeof(unsigned int));
			event->stack_ret[stack_count ++] = *(user_esp);
			event->stack_ret[stack_count ++] = *(user_esp + 1);
			user_ebp = (unsigned int *)*(kstack_base - 7);
			while (1) {
				unsigned int *next_user_ebp;

				ProbeForRead(user_ebp, sizeof(unsigned int) * 2,  sizeof(unsigned int));

				if (*(user_ebp + 1) == 0)
					break;
				event->stack_ret[stack_count ++] = *(user_ebp + 1);

				next_user_ebp = (unsigned int *)*user_ebp;
				if (stack_count >= MAX_STACK_FRAME ||
						next_user_ebp <= user_ebp ||
						next_user_ebp > user_ebp + 8192) // assume no stack frame > 32k
					break;
				user_ebp = next_user_ebp;
			}
		} except (EXCEPTION_EXECUTE_HANDLER) {
			//DbgPrint("x (%d,%d) %p %d %d\n", event->pid, event->tid, user_ebp, step, stack_count);
		}
		event->stack_n = stack_count;
	} else {
		event->stack_n = 0;
	}
#endif

	return event;
}

void event_buffer_finish_add (struct event *event)
{
	int event_i;
	KLOCK_QUEUE_HANDLE lock_handle;

	ASSERT(event);

	event_i = ((char *)event - (char *)event_buffer->pool) / sizeof(struct event);
	event->next = -1;

	KeAcquireInStackQueuedSpinLock(&event_buffer_lock, &lock_handle);
	KeQuerySystemTime(&event->time);
	event->serial = ++ event_buffer->serial;
	if (event_buffer->written_count == 0) {
		event_buffer->written_head = event_buffer->written_tail = event_i;
	} else {
		event_buffer->pool[event_buffer->written_tail].next = event_i;
		event_buffer->written_tail = event_i;
	}
	event_buffer->written_count ++;
	KeReleaseInStackQueuedSpinLock(&lock_handle);

	if ((event_buffer->free_count < EVENT_BUFFER_FREE_THRESHOLD ||
				event_buffer->written_count > EVENT_BUFFER_WRITTEN_THRESHOLD) &&
			!KeReadStateEvent(event_buffer_readyevent))
		KeSetEvent(event_buffer_readyevent, 0, FALSE);
}

void event_buffer_cancel_add (struct event *event)
{
	int event_i;
	KLOCK_QUEUE_HANDLE lock_handle;

	ASSERT(event);

	event_i = ((char *)event - (char *)event_buffer->pool) / sizeof(struct event);

	KeAcquireInStackQueuedSpinLock(&event_buffer_lock, &lock_handle);
	event->next = event_buffer->free_head;
	event_buffer->free_head = event_i;
	event_buffer->free_count ++;
	KeReleaseInStackQueuedSpinLock(&lock_handle);
}

void event_buffer_swap (void)
{
	KLOCK_QUEUE_HANDLE lock_handle;

	KeAcquireInStackQueuedSpinLock(&event_buffer_lock, &lock_handle);
	/* 1. everything in reading list goes to free list */
	if (event_buffer->reading_count != 0) {
		event_buffer->pool[event_buffer->reading_tail].next = event_buffer->free_head;
		event_buffer->free_head = event_buffer->reading_head;
		event_buffer->free_count += event_buffer->reading_count;
	}
	/* 2. everything in written list goes to reading list */
	event_buffer->reading_head = event_buffer->written_head;
	event_buffer->reading_tail = event_buffer->written_tail;
	event_buffer->reading_count = event_buffer->written_count;
	event_buffer->written_head = event_buffer->written_tail = -1;
	event_buffer->written_count = 0;
	KeReleaseInStackQueuedSpinLock(&lock_handle);

	KeClearEvent(event_buffer_readyevent);
}

NTSTATUS event_buffer_init (void)
{
	UNICODE_STRING device_name;
	OBJECT_ATTRIBUTES object_attr;
	LARGE_INTEGER sec_size;
	void *section_object;
	SIZE_T size_not_used = sizeof(struct event_buffer);
	NTSTATUS status;

	/* create shared section object */
	RtlInitUnicodeString(&device_name, L"\\BaseNamedObjects\\resmoneb");
	sec_size.QuadPart = sizeof(struct event_buffer);
	InitializeObjectAttributes(&object_attr, &device_name, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateSection(&event_buffer_section,
			SECTION_ALL_ACCESS,
			&object_attr,
			&sec_size,
			PAGE_READWRITE,
			0x8000000,
			NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ZwCreateSection failed. err=%x\n", status);
		event_buffer_section = NULL; // just in case ZwCreateSection set it.
		goto errout;
	}

	/* map section into system address space */
	status = ObReferenceObjectByHandle(event_buffer_section,
			SECTION_ALL_ACCESS,
			NULL,
			KernelMode,
			&section_object,
			NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("ObReferenceObjectByHandle failed. err=%x\n", status);
		goto errout;
	}
	status = MmMapViewInSystemSpace(section_object, &event_buffer, &size_not_used);
	ObDereferenceObject(section_object);
	section_object = NULL;
	if (status != STATUS_SUCCESS) {
		DbgPrint("MmMapViewInSystemSpace failed. err=%x\n", status);
		event_buffer = NULL; // just in case MmMapViewInSystemSpace set it.
		goto errout;
	}
	DbgPrint("event_buffer mapped at %x\n", (unsigned int)event_buffer);

	/* Lock the section in physical memory */
	event_buffer_mdl = IoAllocateMdl(event_buffer, sizeof(struct event_buffer), FALSE, TRUE, NULL);
	if (event_buffer_mdl == NULL) {
		DbgPrint("IoAllocateMdl failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto errout;
	}
	try {
		//TODO: does IoWriteAccess mean read+write? MSDN doesn't say that.
		MmProbeAndLockPages(event_buffer_mdl, KernelMode, IoWriteAccess);
	} except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("MmProbeAndLockPages failed\n");
		status = GetExceptionCode();
		goto errout;
	}

	/* create ready event */
	RtlInitUnicodeString(&device_name, L"\\BaseNamedObjects\\resmonready");
	event_buffer_readyevent = IoCreateNotificationEvent(&device_name, &event_buffer_readyeventhandle);
	if (event_buffer_readyevent == NULL) {
		DbgPrint("IoCreateNotificationEvent deferred.\n");
		event_buffer_readyeventhandle = NULL;
	} else {
		KeClearEvent(event_buffer_readyevent);
	}

	KeInitializeSpinLock(&event_buffer_lock);

	return STATUS_SUCCESS;

errout:
	if (event_buffer_mdl != NULL) {
		// no need to call MmUnlockPages(event_buffer_mdl)
		// because either it's not reached or failed.
		IoFreeMdl(event_buffer_mdl);
		event_buffer_mdl = NULL;
	}
	if (event_buffer != NULL) {
		MmUnmapViewInSystemSpace(event_buffer);
		event_buffer = NULL;
	}
	if (event_buffer_section != NULL) {
		ZwClose(event_buffer_section);
		event_buffer_section = NULL;
	}
	return status;
}

NTSTATUS event_buffer_start (void)
{
	int i;

	if (event_buffer_readyevent == NULL) {
		UNICODE_STRING device_name;
		RtlInitUnicodeString(&device_name, L"\\BaseNamedObjects\\resmonready");
		event_buffer_readyevent = IoCreateNotificationEvent(&device_name, &event_buffer_readyeventhandle);
		if (event_buffer_readyevent == NULL) {
			DbgPrint("IoCreateNotificationEvent failed.\n");
			event_buffer_readyeventhandle = NULL;
			return STATUS_UNSUCCESSFUL;
		}
	}

	KeClearEvent(event_buffer_readyevent);

	event_buffer->free_head = 0;
	event_buffer->free_count = EVENT_BUFFER_SIZE;
	event_buffer->reading_head = event_buffer->reading_tail = -1;
	event_buffer->reading_count = 0;
	event_buffer->written_head = event_buffer->written_tail = -1;
	event_buffer->written_count = 0;
	event_buffer->serial = 0;
	event_buffer->dropped = 0;
	for (i = 0; i < EVENT_BUFFER_SIZE - 1; i ++)
		event_buffer->pool[i].next = i + 1;
	event_buffer->pool[EVENT_BUFFER_SIZE - 1].next = -1;

	return STATUS_SUCCESS;
}

void event_buffer_stop (void)
{
	// do nothing here
}

void event_buffer_fini (void)
{
	ZwClose(event_buffer_readyeventhandle);
	event_buffer_readyeventhandle = NULL;
	event_buffer_readyevent = NULL;
	MmUnlockPages(event_buffer_mdl);
	IoFreeMdl(event_buffer_mdl);
	event_buffer_mdl = NULL;
	MmUnmapViewInSystemSpace(event_buffer);
	event_buffer = NULL;
	ZwClose(event_buffer_section);
	event_buffer_section = NULL;
}
