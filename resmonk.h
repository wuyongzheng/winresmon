#ifndef RESMON_H
#define RESMON_H

#include <ntddk.h> 
#include "kucomm.h"

extern DRIVER_OBJECT *driver_object;

void event_buffer_add (struct event *event);

NTSTATUS syscall_init (void);
void syscall_fini (void);

NTSTATUS reg_init (void);
void reg_fini (void);

NTSTATUS proc_init (void);
void proc_fini (void);

NTSTATUS file_init (void);
void file_fini (void);

#endif
