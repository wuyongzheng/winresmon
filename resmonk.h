#ifndef RESMON_H
#define RESMON_H

#include <ntddk.h> 
#include "kucomm.h"

/* an htable_entry has 3 status:
 0. freed: after calling htable_free_entry()
 1. allocated or removed: after htable_allocate_entry() or htable_remove_entry()
 2. added: after call htable_add_entry()
 */
struct htable_entry {
	LIST_ENTRY list; // for lru and free_pool
	LIST_ENTRY ht_list; // for hashtable
	int status;
	unsigned long pid;
	HANDLE handle;
	int name_length;
	short name [MAX_PATH_SIZE];
};

extern DRIVER_OBJECT *driver_object;
extern unsigned long daemon_pid;

struct htable_entry *htable_allocate_entry (void);
void htable_free_entry (struct htable_entry *entry);
void htable_add_entry (struct htable_entry *entry);
struct htable_entry *htable_get_entry (unsigned long pid, HANDLE handle);
void htable_remove_entry (struct htable_entry *entry);
void htable_remove_process_entries (unsigned long pid);
NTSTATUS handle_table_init (void);
NTSTATUS handle_table_start (void);
void handle_table_stop (void);
void handle_table_fini (void);

struct event *event_buffer_start_add (void);
void event_buffer_finish_add (void);
void event_buffer_cancel_add (void);
void event_buffer_swap (void);
NTSTATUS event_buffer_init (void);
NTSTATUS event_buffer_start (void);
void event_buffer_stop (void);
void event_buffer_fini (void);

NTSTATUS reg_start (void);
void reg_stop (void);

NTSTATUS proc_start (void);
void proc_stop (void);

NTSTATUS file_start (void);
void file_stop (void);

#endif
