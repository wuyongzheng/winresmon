#ifndef RESMON_H
#define RESMON_H

#include <ntddk.h> 
#include "kucomm.h"

struct htable_entry {
	LIST_ENTRY lru;
	struct htable_entry *next; // for hashtable and free_pool
	unsigned long pid;
	HANDLE handle;
	int name_length; // = 0 when not added, != 0 when added
	short name [MAX_PATH_SIZE];
};

extern DRIVER_OBJECT *driver_object;
extern unsigned long daemon_pid;

NTSTATUS handle_table_init (void);
void handle_table_fini (void);

struct event *event_buffer_start_add (void);
void event_buffer_finish_add (void);
void event_buffer_swap (void);
NTSTATUS event_buffer_init (void);
void event_buffer_fini (void);

NTSTATUS reg_init (void);
void reg_fini (void);

NTSTATUS proc_init (void);
void proc_fini (void);

NTSTATUS file_init (void);
void file_fini (void);

#endif
