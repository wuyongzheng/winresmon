#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "kucomm.h"

HANDLE stop_event;

DWORD service_init (void)
{
	stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (stop_event == NULL) {
		OutputDebugString("CreateEvent() failed\n");
		return GetLastError();
	}

	return 0;
}

DWORD service_process (void)
{
	if (WaitForSingleObject(stop_event, INFINITE) == WAIT_FAILED) {
		OutputDebugString("WaitForSingleObject() failed\n");
		return GetLastError();
	}
	return 0;
}

DWORD service_fini (void)
{
	CloseHandle(stop_event);
	return 0;
}

DWORD WINAPI service_handler (DWORD control_code, DWORD event_type, void *data, void *context)
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

void WINAPI service_main (DWORD argc, char *argv[])
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

int run_service (void)
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

int run_console (void)
{
	return 1;
}

int install (void)
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
			NULL,//"resmonk\0\0",
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

int uninstall (void)
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

void help (void)
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
