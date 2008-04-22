#ifndef RESMON_H
#define RESMON_H

#include <ntddk.h> 
#include "kucomm.h"

/* an htable_entry has 3 status:
 * 0. allocated     returned by htable_allocate_entry()
 * 1. added +refc   after calling htable_add_entry() (on lru list and hashtable)
 * 2. freeing +refc 
 * 3. freed         (on free_pool list)
 */
enum htable_entry_status {
	HTES_ALLOCATED, HTES_ADDED, HTES_FREEING, HTES_FREED
};
struct htable_entry {
	enum htable_entry_status status;
	int reference_count;
	LIST_ENTRY list; // for lru and free_pool
	LIST_ENTRY ht_list; // for hashtable
	unsigned long pid;
	HANDLE handle;
	int name_length;
	unsigned short name [MAX_PATH_SIZE]; // always '\0' terminated
};

extern DRIVER_OBJECT *driver_object;
extern unsigned long daemon_pid;

#ifdef USERDTSC
LARGE_INTEGER __cdecl get_timestamp (void);
#else
#define get_timestamp() KeQueryPerformanceCounter(NULL);
#endif

struct htable_entry *htable_allocate_entry (void);
struct htable_entry *htable_get_entry (unsigned long pid, HANDLE handle);
void htable_put_entry (struct htable_entry *entry);
void htable_add_entry (struct htable_entry *entry);
void htable_remove_entry (struct htable_entry *entry);
void htable_remove_process_entries (unsigned long pid);
NTSTATUS handle_table_init (void);
NTSTATUS handle_table_start (void);
void handle_table_stop (void);
void handle_table_fini (void);

struct event *event_buffer_start_add (void);
void event_buffer_finish_add (struct event *);
void event_buffer_cancel_add (struct event *);
void event_buffer_swap (void);
NTSTATUS event_buffer_init (void);
NTSTATUS event_buffer_start (void);
void event_buffer_stop (void);
void event_buffer_fini (void);

NTSTATUS tdi_start (void);
void tdi_stop (void);
NTSTATUS tdi_init (void);
void tdi_fini (void);

NTSTATUS reg_start (void);
void reg_stop (void);

NTSTATUS proc_start (void);
void proc_stop (void);

NTSTATUS file_start (void);
void file_stop (void);

#endif
