#include <ntddk.h>
#include "resmonk.h"

#define SYSCALLNO_NtAlertResumeThread 12
#define INTERVAL_SEC 30

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;
	PULONG Count;
	ULONG Limit;
	PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

static NTSTATUS (*_NtAlertResumeThread) (HANDLE ThreadHandle, PULONG SuspendCount);
static HANDLE thread_handle;
static int timer_running = 0; // only modified by the worker thread
static int timer_continue; // only modified by the controler thread

static void work (void)
{
	DbgPrint("resmon.timer: work()\n");
}

static void worker_thread (void *start_context)
{
	NTSTATUS status;

	if (!timer_continue) {
		DbgPrint("resmon.timer: thread_entry entered with timer_continue = false\n");
		status = PsTerminateSystemThread(STATUS_OBJECT_NAME_EXISTS);
		DbgPrint("resmon.timer: PsTerminateSystemThread failed. status=%x\n", status);
		return;
	}
	if (timer_running) {
		DbgPrint("resmon.timer: thread_entry entered with timer_running = true\n");
		status = PsTerminateSystemThread(STATUS_OBJECT_NAME_EXISTS);
		DbgPrint("resmon.timer: PsTerminateSystemThread failed. status=%x\n", status);
		return;
	}
	timer_running = 1;
	DbgPrint("resmon.timer: worker thread started\n");

	while (1) {
		LARGE_INTEGER interval;

		work();

		interval.QuadPart = -(long long)INTERVAL_SEC * 1000 * 1000 * 10;
		status = KeDelayExecutionThread(KernelMode, TRUE, &interval);
		if (!timer_continue) {
			DbgPrint("resmon.timer: worker thread stopping. (if no error, it's stopped.)\n");
			timer_running = 0;
			status = PsTerminateSystemThread(STATUS_OBJECT_NAME_EXISTS);
			DbgPrint("resmon.timer: PsTerminateSystemThread failed. status=%x\n", status);
			return;
		}
		if (status != STATUS_SUCCESS) {
			DbgPrint("resmon.timer: timer_continue = true, but KeDelayExecutionThread returns %x. still running.\n", status);
		}
	}
}

NTSTATUS timer_start (void)
{
	NTSTATUS status;

	if (_NtAlertResumeThread == NULL) {
		_NtAlertResumeThread = ((void **)KeServiceDescriptorTable->Base)[SYSCALLNO_NtAlertResumeThread];
	}

	timer_continue = 1;
	status = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, worker_thread, NULL);
	if (status != STATUS_SUCCESS) {
		DbgPrint("resmon.timer: PsCreateSystemThread failed with %x\n", status);
		return status;
	}

	return STATUS_SUCCESS;
}

void timer_stop (void)
{
	NTSTATUS status;
	ULONG count;

	timer_continue = 0;
	status = _NtAlertResumeThread(thread_handle, &count);
	if (status != STATUS_SUCCESS) {
		DbgPrint("resmon.timer: NtAlertResumeThread failed with %x\n", status);
	}
	thread_handle = NULL;
}
