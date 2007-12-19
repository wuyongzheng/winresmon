#include <ntddk.h>

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
