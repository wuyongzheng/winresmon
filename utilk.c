#include <ntddk.h>
#include "resmonk.h"
#include "stdarg.h"
#include "stdio.h"

#ifdef USERDTSC
__declspec(naked)
LARGE_INTEGER __cdecl get_timestamp (void)
{
	__asm {
		rdtsc;
		ret;
	}
}
#endif

void add_debug_event (const char *format, ...)
{
	va_list arglist;
	struct event *event;

	event = event_buffer_start_add();
	if (event == NULL)
		return;

	event->type = ET_DEBUG;
	event->status = STATUS_SUCCESS;
	event->time_pre = event->time_post = get_timestamp();
	event->path_length = 0;
	va_start(arglist, format);
	_vsnprintf(event->debug.message, MAX_IO_SIZE, format, arglist);
	event->debug.message[MAX_IO_SIZE - 1] = '\0';
	event_buffer_finish_add(event);
}
