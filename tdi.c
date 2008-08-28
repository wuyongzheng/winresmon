/* refferenced doc and code:
 * http://www.ntkernel.com/forum/viewtopic.php?t=294&sid=99695d308a37deff890cd4a8b6658f33
 * http://tdifw.sourceforge.net/
 */

#include <ntddk.h>
#include <tdikrnl.h>
#include "resmonk.h"

#define NUM_EVENTS 11
#define FOHT_SIZE 2007
#define FOHT_HASH(addr) ((unsigned int)(addr) % FOHT_SIZE)

#define foht_lock() KeAcquireSpinLock(&foht_spin_lock, &foht_lock_oldirq)
#define foht_unlock() KeReleaseSpinLock(&foht_spin_lock, foht_lock_oldirq)
// caller doesn't hold lock for foht_allocate and foht_free
#define foht_allocate() ((struct foht_entry *)ExAllocateFromNPagedLookasideList(&foht_pool))
#define foht_free(entry) ExFreeToNPagedLookasideList(&foht_pool, entry)

#define ESCAPE_CONDITION (unsigned long)PsGetCurrentProcessId() == daemon_pid

NTKERNELAPI NTSTATUS ObReferenceObjectByName (PUNICODE_STRING ObjectPath,
		ULONG Attributes,
		PACCESS_STATE PassedAccessState,
		ACCESS_MASK DesiredAccess,
		POBJECT_TYPE ObjectType,
		KPROCESSOR_MODE AccessMode,
		PVOID ParseContext,
		PVOID* ObjectPtr);
extern POBJECT_TYPE IoDriverObjectType;

struct tdimon_context {
	unsigned int minor_function;
	char parameters[16];
	FILE_OBJECT *file_object;
	PIO_COMPLETION_ROUTINE orig_cr;
	LARGE_INTEGER time_pre;
	unsigned long pid;
	unsigned long tid;
	void *orig_context;
	int orig_control;
};

/* foht: file object hash table */
struct foht_entry {
	struct foht_entry *next;
	DEVICE_OBJECT *device_object;
	FILE_OBJECT *file_object;
	unsigned long pid;
	unsigned long tid;
	void *orig_handler[NUM_EVENTS];
	void *orig_context[NUM_EVENTS];
};

static NPAGED_LOOKASIDE_LIST context_list;
static NPAGED_LOOKASIDE_LIST foht_pool;
static struct foht_entry *foht[FOHT_SIZE];
static struct foht_entry *foht_removed_entries;
static KSPIN_LOCK foht_spin_lock;
static KIRQL foht_lock_oldirq;


static void store_trans_addr (struct tdi_transport_address *my_addr,
		const TRANSPORT_ADDRESS *trans_addr)
{
	int i;

	my_addr->family = 0;
	if (trans_addr == NULL || trans_addr->TAAddressCount == 0)
		return;

	for (i = 0; i < trans_addr->TAAddressCount; i ++) {
		if (trans_addr->Address[i].AddressType == TDI_ADDRESS_TYPE_IP) {
			TDI_ADDRESS_IP *ip_addr = (TDI_ADDRESS_IP *)(trans_addr->Address[i].Address);
			my_addr->family = 2;
			my_addr->ipv4.port = ip_addr->sin_port;
			RtlCopyMemory(my_addr->ipv4.addr, &ip_addr->in_addr, 4);
			return;
		}
	}

	for (i = 0; i < trans_addr->TAAddressCount; i ++) {
		if (trans_addr->Address[i].AddressType == TDI_ADDRESS_TYPE_IP6) {
			TDI_ADDRESS_IP6 *ip6_addr = (TDI_ADDRESS_IP6 *)(trans_addr->Address[i].Address);
			my_addr->family = 23;
			my_addr->ipv6.port = ip6_addr->sin6_port;
			RtlCopyMemory(my_addr->ipv6.addr, &ip6_addr->sin6_addr, 16);
			return;
		}
	}
}

static void store_conninfor (struct tdi_transport_address *my_addr,
		const TDI_CONNECTION_INFORMATION *conn_information)
{
	if (conn_information != NULL && conn_information->RemoteAddressLength > 0)
		store_trans_addr(my_addr, (TRANSPORT_ADDRESS *)conn_information->RemoteAddress);
	else
		my_addr->family = 0;
}

static struct foht_entry *foht_get (FILE_OBJECT *file_object)
{
	struct foht_entry *entry = foht[FOHT_HASH(file_object)];
	while (entry != NULL && entry->file_object != file_object)
		entry = entry->next;
	return entry;
}

/* Just remove it from hash table. caller should free the entry.
 * Called at IRP_MJ_CLEANUP */
static void foht_remove (struct foht_entry *entry_to_remove)
{
	struct foht_entry *entry = foht[FOHT_HASH(entry_to_remove->file_object)];
	if (entry == NULL) {
		DbgPrint("tdimon: foht_remove: removing non-existing entry (entry=%08x, fobj=%08x). ignored.\n",
				entry_to_remove, entry_to_remove->file_object);
		return;
	}
	if (entry == entry_to_remove) {
		foht[FOHT_HASH(entry->file_object)] = entry->next;
		return;
	}
	while (entry->next != NULL && entry->next != entry_to_remove)
		entry = entry->next;
	if (entry->next == NULL) {
		DbgPrint("tdimon: foht_remove: removing non-existing entry (entry=%08x, fobj=%08x). ignored.\n",
				entry_to_remove, entry_to_remove->file_object);
	} else {
		entry->next = entry_to_remove->next;
	}
}

/* If existing file_object is found, it refuse to add */
static void foht_add (struct foht_entry *new_entry)
{
	struct foht_entry *entry = foht[FOHT_HASH(new_entry->file_object)];
	while (entry != NULL && entry->file_object != new_entry->file_object)
		entry = entry->next;
	if (entry != NULL) {
		DbgPrint("tdimon: foht_add: fobj %08x already in the table. olde=%08x, newe=%08x. not added.",
				new_entry->file_object, entry, new_entry);
		return;
	}
	new_entry->next = foht[FOHT_HASH(new_entry->file_object)];
	foht[FOHT_HASH(new_entry->file_object)] = new_entry;
}

/* Unregister all event handler and removes the foht_entry,
 * but do not free it because it may still be accessed by handlers.
 * In practice, everything in foht[] is put into foht_removed_entries.
 * Caller must not holding the lock. */
static void foht_remove_all (void)
{
	/* Make sure IoCallDriver is not inside spinlock.
	 * This is as slow as O(n^2).
	 * Delay deallocation */
	for (;;) {
		unsigned int hash;
		struct foht_entry *entry;

		foht_lock();
		for (hash = 0; hash < FOHT_SIZE && foht[hash] == NULL; hash ++)
			;
		entry = (hash < FOHT_SIZE) ? foht[hash] : NULL;
		if (entry != NULL)
			foht_remove(entry);
		foht_unlock();

		if (entry == NULL)
			break;

		for (hash = 0; hash < NUM_EVENTS; hash ++) {
			PIRP query_irp;
			NTSTATUS status;

			if (entry->orig_handler[hash] == NULL)
				continue;

			query_irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER,
					entry->device_object, entry->file_object, NULL, NULL);
			ASSERT(query_irp != NULL);
			TdiBuildSetEventHandler(query_irp, entry->device_object, entry->file_object,
					NULL, NULL, hash, entry->orig_handler[hash], entry->orig_context[hash]);
			status = IoCallDriver(entry->device_object, query_irp);
			DbgPrint("tdimon: foht_fini: restore event "
					"(entry=%08x, fobj=%08x, type=%d, handler=%08x, context=%08x) = %x\n",
					entry, entry->file_object,
					hash, entry->orig_handler[hash], entry->orig_context[hash],
					status);
		}

		entry->next = foht_removed_entries;
		foht_removed_entries = entry;
	}
}

/* Free everything in foht_removed_entries */
static void foht_free_removed_entries (void)
{
	while (foht_removed_entries != NULL) {
		struct foht_entry *next = foht_removed_entries->next;
		foht_free(foht_removed_entries);
		foht_removed_entries = next;
	}
}

static NTSTATUS foht_init (void)
{
	KeInitializeSpinLock(&foht_spin_lock);
	foht_removed_entries = NULL;
	RtlZeroMemory(foht, FOHT_SIZE * sizeof(struct foht_entry *));
	ExInitializeNPagedLookasideList(&foht_pool, NULL, NULL, 0,
			sizeof(struct foht_entry),
			0x544f4d54, // TMOT: tdimon object table
			0);
	return STATUS_SUCCESS;
}

static void foht_fini (void)
{
	foht_remove_all(); // It's already called in tdi_stop(), but it doesn't harm to call it again.
	foht_free_removed_entries();
	ExDeleteNPagedLookasideList(&foht_pool);
}

static NTSTATUS tdimon_eh_connect (
	struct foht_entry *entry,
	long remote_address_length,
	void *remote_address,
	long user_data_length,
	void *user_data,
	long options_length,
	void *options,
	CONNECTION_CONTEXT *connection_context,
	IRP **accept_irp)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_CONNECT)entry->orig_handler[TDI_EVENT_CONNECT])(
			entry->orig_context[TDI_EVENT_DISCONNECT],
			remote_address_length,
			remote_address,
			user_data_length,
			user_data,
			options_length,
			options,
			connection_context,
			accept_irp);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_CONNECT;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_connect.file_object = entry->file_object;
		store_trans_addr(&event->tdi_event_connect.addr, (TRANSPORT_ADDRESS *)remote_address);
		event->tdi_event_connect.user_data_length = user_data_length;
		event->tdi_event_connect.options_length = options_length;
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_disconnect (
	struct foht_entry *entry,
	CONNECTION_CONTEXT connection_context,
	long disconnect_data_length,
	void *disconnect_data,
	long disconnect_information_length,
	void *disconnect_information,
	unsigned long disconnect_flags)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_DISCONNECT)entry->orig_handler[TDI_EVENT_DISCONNECT])(
			entry->orig_context[TDI_EVENT_DISCONNECT],
			connection_context,
			disconnect_data_length,
			disconnect_data,
			disconnect_information_length,
			disconnect_information,
			disconnect_flags);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_DISCONNECT;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_disconnect.file_object = entry->file_object;
		event->tdi_event_disconnect.data_length = disconnect_data_length;
		event->tdi_event_disconnect.information_length = disconnect_information_length;
		event->tdi_event_disconnect.flags = disconnect_flags;
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_error (
	struct foht_entry *entry,
	NTSTATUS cause_status)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_ERROR)entry->orig_handler[TDI_EVENT_ERROR])(
			entry->orig_context[TDI_EVENT_ERROR],
			cause_status);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_ERROR;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_error.file_object = entry->file_object;
		event->tdi_event_error.cause_status = cause_status;
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_receive (
	struct foht_entry *entry,
	CONNECTION_CONTEXT connection_context,
	unsigned long receive_flags,
	unsigned long bytes_indicated,
	unsigned long bytes_available,
	unsigned long *bytes_taken,
	void *tsdu,
	IRP **io_request_packet)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_RECEIVE)entry->orig_handler[TDI_EVENT_RECEIVE])(
			entry->orig_context[TDI_EVENT_RECEIVE],
			connection_context,receive_flags,
			bytes_indicated,
			bytes_available,
			bytes_taken,
			tsdu,
			io_request_packet);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_RECEIVE;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_receive.file_object = entry->file_object;
		event->tdi_event_receive.flags = receive_flags;
		event->tdi_event_receive.bytes_indicated = bytes_indicated;
		event->tdi_event_receive.bytes_available = bytes_available;
		event->tdi_event_receive.bytes_taken = bytes_taken == NULL ? 0 : *bytes_taken;
		RtlCopyMemory(event->tdi_event_receive.data, tsdu,
				bytes_indicated < MAX_IO_SIZE ? bytes_indicated : MAX_IO_SIZE);
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_receive_datagram (
	struct foht_entry *entry,
	long source_address_length,
	void *source_address,
	long options_length,
	void *options,
	unsigned long receive_datagram_flags,
	unsigned long bytes_indicated,
	unsigned long bytes_available,
	unsigned long *bytes_taken,
	void *tsdu,
	IRP **io_request_packet)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_RECEIVE_DATAGRAM)entry->orig_handler[TDI_EVENT_RECEIVE_DATAGRAM])(
			entry->orig_context[TDI_EVENT_RECEIVE_DATAGRAM],
			source_address_length,
			source_address,
			options_length,
			options,
			receive_datagram_flags,
			bytes_indicated,
			bytes_available,
			bytes_taken,
			tsdu,
			io_request_packet);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_RECEIVE_DATAGRAM;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_receive_datagram.file_object = entry->file_object;
		store_trans_addr(&event->tdi_event_receive_datagram.addr, (TRANSPORT_ADDRESS *)source_address);
		event->tdi_event_receive_datagram.options_length = options_length;
		event->tdi_event_receive_datagram.flags = receive_datagram_flags;
		event->tdi_event_receive_datagram.bytes_indicated = bytes_indicated;
		event->tdi_event_receive_datagram.bytes_available = bytes_available;
		event->tdi_event_receive_datagram.bytes_taken = bytes_taken == NULL ? 0 : *bytes_taken;
		RtlCopyMemory(event->tdi_event_receive_datagram.data, tsdu,
				bytes_indicated < MAX_IO_SIZE ? bytes_indicated : MAX_IO_SIZE);
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_receive_expedited (
	struct foht_entry *entry,
	CONNECTION_CONTEXT connection_context,
	unsigned long receive_flags,
	unsigned long bytes_indicated,
	unsigned long bytes_available,
	unsigned long *bytes_taken,
	void *tsdu,
	IRP **io_request_packet)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_RECEIVE_EXPEDITED)entry->orig_handler[TDI_EVENT_RECEIVE_EXPEDITED])(
			entry->orig_context[TDI_EVENT_RECEIVE_EXPEDITED],
			connection_context,
			receive_flags,
			bytes_indicated,
			bytes_available,
			bytes_taken,
			tsdu,
			io_request_packet);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_RECEIVE_EXPEDITED;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_receive.file_object = entry->file_object;
		event->tdi_event_receive.flags = receive_flags;
		event->tdi_event_receive.bytes_indicated = bytes_indicated;
		event->tdi_event_receive.bytes_available = bytes_available;
		event->tdi_event_receive.bytes_taken = bytes_taken == NULL ? 0 : *bytes_taken;
		RtlCopyMemory(event->tdi_event_receive.data, tsdu,
				bytes_indicated < MAX_IO_SIZE ? bytes_indicated : MAX_IO_SIZE);
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_send_possible (
	struct foht_entry *entry,
	void *connection_context,
	unsigned long bytes_available)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_SEND_POSSIBLE)entry->orig_handler[TDI_EVENT_SEND_POSSIBLE])(
			entry->orig_context[TDI_EVENT_SEND_POSSIBLE],
			connection_context,
			bytes_available);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_SEND_POSSIBLE;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_send_possible.file_object = entry->file_object;
		event->tdi_event_send_possible.bytes_available = bytes_available;
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_chained_receive (
	struct foht_entry *entry,
	CONNECTION_CONTEXT connection_context,
	unsigned long receive_flags,
	unsigned long receive_length,
	unsigned long starting_offset,
	MDL *tsdu,
	void *tsdu_descriptor)
{
	struct event *event;
	NTSTATUS status;
	char *data;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_CHAINED_RECEIVE)entry->orig_handler[TDI_EVENT_CHAINED_RECEIVE])(
			entry->orig_context[TDI_EVENT_CHAINED_RECEIVE],
			connection_context,
			receive_flags,
			receive_length,
			starting_offset,
			tsdu,
			tsdu_descriptor);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if (receive_length > 0)
		data = (char *)MmGetSystemAddressForMdlSafe(tsdu, NormalPagePriority);
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_CHAINED_RECEIVE;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_chained_receive.file_object = entry->file_object;
		event->tdi_event_chained_receive.flags = receive_flags;
		event->tdi_event_chained_receive.length = receive_length;
		if (receive_length > 0 && data != NULL)
			RtlCopyMemory(event->tdi_event_chained_receive.data, data + starting_offset,
					receive_length < MAX_IO_SIZE ? receive_length : MAX_IO_SIZE);
		// TODO: what if data = NULL and receive_length > 0?
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_chained_receive_datagram (
	struct foht_entry *entry,
	long source_address_length,
	void *source_address,
	long options_length,
	void *options,
	unsigned long receive_datagram_flags,
	unsigned long receive_datagram_length,
	unsigned long starting_offset,
	MDL *tsdu,
	void *tsdu_descriptor)
{
	struct event *event;
	NTSTATUS status;
	char *data;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_CHAINED_RECEIVE_DATAGRAM)entry->orig_handler[TDI_EVENT_CHAINED_RECEIVE_DATAGRAM])(
			entry->orig_context[TDI_EVENT_CHAINED_RECEIVE_DATAGRAM],
			source_address_length,
			source_address,
			options_length,
			options,
			receive_datagram_flags,
			receive_datagram_length,
			starting_offset,
			tsdu,
			tsdu_descriptor);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if (receive_datagram_length > 0)
		data = (char *)MmGetSystemAddressForMdlSafe(tsdu, NormalPagePriority);
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_CHAINED_RECEIVE_DATAGRAM;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_chained_receive_datagram.file_object = entry->file_object;
		store_trans_addr(&event->tdi_event_chained_receive_datagram.addr,
				(TRANSPORT_ADDRESS *)source_address);
		event->tdi_event_chained_receive_datagram.options_length = options_length;
		event->tdi_event_chained_receive_datagram.flags = receive_datagram_flags;
		event->tdi_event_chained_receive_datagram.length = receive_datagram_length;
		if (receive_datagram_length > 0 && data != NULL)
			RtlCopyMemory(event->tdi_event_chained_receive_datagram.data, data + starting_offset,
					receive_datagram_length < MAX_IO_SIZE ? receive_datagram_length : MAX_IO_SIZE);
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_chained_receive_expedited (
	struct foht_entry *entry,
	CONNECTION_CONTEXT connection_context,
	unsigned long receive_flags,
	unsigned long receive_length,
	unsigned long starting_offset,
	MDL *tsdu,
	void *tsdu_descriptor)
{
	struct event *event;
	NTSTATUS status;
	char *data;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_CHAINED_RECEIVE_EXPEDITED)entry->orig_handler[TDI_EVENT_CHAINED_RECEIVE_EXPEDITED])(
			entry->orig_context[TDI_EVENT_CHAINED_RECEIVE_EXPEDITED],
			connection_context,
			receive_flags,
			receive_length,
			starting_offset,
			tsdu,
			tsdu_descriptor);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if (receive_length > 0)
		data = (char *)MmGetSystemAddressForMdlSafe(tsdu, NormalPagePriority);
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_CHAINED_RECEIVE_EXPEDITED;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_chained_receive.file_object = entry->file_object;
		event->tdi_event_chained_receive.flags = receive_flags;
		event->tdi_event_chained_receive.length = receive_length;
		if (receive_length > 0 && data != NULL)
			RtlCopyMemory(event->tdi_event_chained_receive.data, data + starting_offset,
					receive_length < MAX_IO_SIZE ? receive_length : MAX_IO_SIZE);
		event_buffer_finish_add(event);
	}
	return status;
}

static NTSTATUS tdimon_eh_error_ex (
	struct foht_entry *entry,
	NTSTATUS cause_status,
	void *buffer)
{
	struct event *event;
	NTSTATUS status;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = (*(PTDI_IND_ERROR_EX)entry->orig_handler[TDI_EVENT_ERROR_EX])(
			entry->orig_context[TDI_EVENT_ERROR_EX],
			cause_status,
			buffer);
	time_post = get_timestamp();
	if (ESCAPE_CONDITION)
		return status;
	if ((event = event_buffer_start_add()) != NULL) {
		event->pid = entry->pid;
		event->tid = entry->tid;
		event->type = ET_TDI_EVENT_ERROR_EX;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_event_error_ex.file_object = entry->file_object;
		event->tdi_event_error_ex.cause_status = cause_status;
		event->tdi_event_error_ex.buffer[0] = '\0'; //TODO: how to use the buffer?
		event_buffer_finish_add(event);
	}
	return status;
}

// must match TDI_EVENT_*
static void *tdimon_event_handlers[NUM_EVENTS] = {
	tdimon_eh_connect,
	tdimon_eh_disconnect,
	tdimon_eh_error,
	tdimon_eh_receive,
	tdimon_eh_receive_datagram,
	tdimon_eh_receive_expedited,
	tdimon_eh_send_possible,
	tdimon_eh_chained_receive,
	tdimon_eh_chained_receive_datagram,
	tdimon_eh_chained_receive_expedited,
	tdimon_eh_error_ex};

static NTSTATUS tdimon_idc_cr (DEVICE_OBJECT *device_object, IRP *irp, struct tdimon_context *context)
{
	NTSTATUS status;
	struct event *event;

	if (ESCAPE_CONDITION)
		goto out;

	event = event_buffer_start_add();
	if (event == NULL)
		goto out;
	event->pid = context->pid;
	event->tid = context->tid;
	event->status = irp->IoStatus.Status;
	event->time_pre = context->time_pre;
	event->time_post = get_timestamp();
	event->path_length = 0;
	event->path[0] = 0;

	switch (context->minor_function) {
	case TDI_ACCEPT:
		event->type = ET_TDI_ACCEPT;
		event->tdi_accept.file_object = context->file_object;
		store_conninfor(&event->tdi_accept.request_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->RequestConnectionInformation);
		store_conninfor(&event->tdi_accept.return_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->ReturnConnectionInformation);
		break;
	case TDI_ACTION:
		event->type = ET_TDI_ACTION;
		event->tdi_general.file_object = context->file_object;
		break;
	case TDI_ASSOCIATE_ADDRESS: {
		FILE_OBJECT *file_obj = NULL;
		status = ObReferenceObjectByHandle(((TDI_REQUEST_KERNEL_ASSOCIATE *)context->parameters)->AddressHandle,
				0,
				*IoFileObjectType,
				KernelMode,
				&file_obj,
				NULL);
		if (status == STATUS_SUCCESS) {
		} else {
			file_obj = NULL;
		}
		event->type = ET_TDI_ASSOCIATE_ADDRESS;
		event->tdi_associate_address.file_object = context->file_object;
		event->tdi_associate_address.file_object2 = file_obj;
		if (file_obj != NULL)
			ObDereferenceObject(file_obj);
		break;
	}
	case TDI_CONNECT:
		event->type = ET_TDI_CONNECT;
		event->tdi_connect.file_object = context->file_object;
		store_conninfor(&event->tdi_connect.request_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->RequestConnectionInformation);
		store_conninfor(&event->tdi_connect.return_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->ReturnConnectionInformation);
		event->tdi_connect.timeout.QuadPart =
			((TDI_REQUEST_KERNEL *)context->parameters)->RequestSpecific == NULL ? 0:
			*(long long *)((TDI_REQUEST_KERNEL *)context->parameters)->RequestSpecific;
		break;
	case TDI_DISASSOCIATE_ADDRESS:
		event->type = ET_TDI_DISASSOCIATE_ADDRESS;
		event->tdi_general.file_object = context->file_object;
		break;
	case TDI_DISCONNECT:
		event->type = ET_TDI_DISCONNECT;
		event->tdi_disconnect.file_object = context->file_object;
		event->tdi_disconnect.flags = ((TDI_REQUEST_KERNEL *)context->parameters)->RequestFlags;
		store_conninfor(&event->tdi_disconnect.request_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->RequestConnectionInformation);
		store_conninfor(&event->tdi_disconnect.return_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->ReturnConnectionInformation);
		event->tdi_disconnect.timeout.QuadPart =
			((TDI_REQUEST_KERNEL *)context->parameters)->RequestSpecific == NULL ? 0 :
			*(long long *)((TDI_REQUEST_KERNEL *)context->parameters)->RequestSpecific;
		break;
	case TDI_LISTEN:
		event->type = ET_TDI_LISTEN;
		event->tdi_listen.file_object = context->file_object;
		event->tdi_listen.flags = ((TDI_REQUEST_KERNEL *)context->parameters)->RequestFlags;
		store_conninfor(&event->tdi_listen.request_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->RequestConnectionInformation);
		store_conninfor(&event->tdi_listen.return_addr,
				((TDI_REQUEST_KERNEL *)context->parameters)->ReturnConnectionInformation);
		break;
	case TDI_QUERY_INFORMATION: {
		TDI_REQUEST_KERNEL_QUERY_INFORMATION *info = (TDI_REQUEST_KERNEL_QUERY_INFORMATION *)context->parameters;
		char *mdl_address = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		event->type = ET_TDI_QUERY_INFORMATION;
		event->tdi_query_information.file_object = context->file_object;
		event->tdi_query_information.type = info->QueryType;
		store_conninfor(&event->tdi_query_information.addr, info->RequestConnectionInformation);
		if (mdl_address != NULL) {
			switch (event->tdi_query_information.type) {
			case TDI_QUERY_ADDRESS_INFO:
				event->tdi_query_information.address.activity_count =
					((TDI_ADDRESS_INFO *)mdl_address)->ActivityCount;
				store_trans_addr(&event->tdi_query_information.address.addr,
						&((TDI_ADDRESS_INFO *)mdl_address)->Address);
				break;
			case TDI_QUERY_CONNECTION_INFO:
				RtlCopyMemory(&event->tdi_query_information.connection,
						mdl_address, sizeof(TDI_CONNECTION_INFO));
				break;
			}
		}
		// TODO: else?
		break;
	}
	case TDI_RECEIVE: {
		char *mdl_address = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		event->type = ET_TDI_RECEIVE;
		event->tdi_receive.file_object = context->file_object;
		event->tdi_receive.length = ((TDI_REQUEST_KERNEL_RECEIVE *)context->parameters)->ReceiveLength;
		event->tdi_receive.flags = ((TDI_REQUEST_KERNEL_RECEIVE *)context->parameters)->ReceiveFlags;
		if (mdl_address != NULL && event->tdi_receive.length > 0)
			RtlCopyMemory(event->tdi_receive.data,
					mdl_address,// + MmGetMdlByteOffset(irp->MdlAddress),
					event->tdi_receive.length < MAX_IO_SIZE ?
					event->tdi_receive.length : MAX_IO_SIZE);
		// TODO: what if mdl_address == NULL and event->tdi_receive.length > 0?
		// same for all TDI_RECEIVE_* below
		break;
	}
	case TDI_RECEIVE_DATAGRAM: {
		char *mdl_address = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		event->type = ET_TDI_RECEIVE_DATAGRAM;
		event->tdi_receive_datagram.file_object = context->file_object;
		event->tdi_receive_datagram.length = ((TDI_REQUEST_KERNEL_RECEIVEDG *)context->parameters)->ReceiveLength;
		event->tdi_receive_datagram.flags = ((TDI_REQUEST_KERNEL_RECEIVEDG *)context->parameters)->ReceiveFlags;
		store_conninfor(&event->tdi_receive_datagram.request_addr,
				((TDI_REQUEST_KERNEL_RECEIVEDG *)context->parameters)->ReceiveDatagramInformation);
		store_conninfor(&event->tdi_receive_datagram.return_addr,
				((TDI_REQUEST_KERNEL_RECEIVEDG *)context->parameters)->ReturnDatagramInformation);
		if (mdl_address != NULL && event->tdi_receive_datagram.length > 0)
			RtlCopyMemory(event->tdi_receive_datagram.data,
					mdl_address,// + MmGetMdlByteOffset(irp->MdlAddress),
					event->tdi_receive_datagram.length < MAX_IO_SIZE ?
					event->tdi_receive_datagram.length : MAX_IO_SIZE);
		break;
	}
	case TDI_SEND: {
		char *mdl_address = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		event->type = ET_TDI_SEND;
		event->tdi_send.file_object = context->file_object;
		event->tdi_send.length = ((TDI_REQUEST_KERNEL_SEND *)context->parameters)->SendLength;
		event->tdi_send.flags = ((TDI_REQUEST_KERNEL_SEND *)context->parameters)->SendFlags;
		if (mdl_address != NULL && event->tdi_send.length > 0)
			RtlCopyMemory(event->tdi_send.data,
					mdl_address,// + MmGetMdlByteOffset(irp->MdlAddress),
					event->tdi_send.length < MAX_IO_SIZE ?
					event->tdi_send.length : MAX_IO_SIZE);
		break;
	}
	case TDI_SEND_DATAGRAM: {
		char *mdl_address = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		event->type = ET_TDI_SEND_DATAGRAM;
		event->tdi_send_datagram.file_object = context->file_object;
		event->tdi_send_datagram.length = ((TDI_REQUEST_KERNEL_SENDDG *)context->parameters)->SendLength;
		store_conninfor(&event->tdi_send_datagram.addr,
				((TDI_REQUEST_KERNEL_SENDDG *)context->parameters)->SendDatagramInformation);
		if (mdl_address != NULL && event->tdi_send_datagram.length > 0)
			RtlCopyMemory(event->tdi_send_datagram.data,
					mdl_address,// + MmGetMdlByteOffset(irp->MdlAddress),
					event->tdi_send_datagram.length < MAX_IO_SIZE ?
					event->tdi_send_datagram.length : MAX_IO_SIZE);
		break;
	}
	case TDI_SET_EVENT_HANDLER:
//		add_debug_event("SETEH pid=%d, type=%d, func=%08x", (int)PsGetCurrentProcessId(),
//				((TDI_REQUEST_KERNEL_SET_EVENT *)context->parameters)->EventType,
//				((TDI_REQUEST_KERNEL_SET_EVENT *)context->parameters)->EventHandler);
		event->type = ET_TDI_SET_EVENT_HANDLER;
		event->tdi_set_event_handler.file_object = context->file_object;
		event->tdi_set_event_handler.type = ((TDI_REQUEST_KERNEL_SET_EVENT *)context->parameters)->EventType;
		event->tdi_set_event_handler.handler = ((TDI_REQUEST_KERNEL_SET_EVENT *)context->parameters)->EventHandler;
		event->tdi_set_event_handler.context = ((TDI_REQUEST_KERNEL_SET_EVENT *)context->parameters)->EventContext;
		break;
	case TDI_SET_INFORMATION: {
		TDI_REQUEST_KERNEL_SET_INFORMATION *info = (TDI_REQUEST_KERNEL_SET_INFORMATION *)context->parameters;
		char *mdl_address = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		event->type = ET_TDI_SET_INFORMATION;
		event->tdi_query_information.file_object = context->file_object;
		event->tdi_query_information.type = info->SetType;
		store_conninfor(&event->tdi_query_information.addr, info->RequestConnectionInformation);
		if (mdl_address != NULL) {
			switch (event->tdi_query_information.type) {
			case TDI_QUERY_ADDRESS_INFO:
				event->tdi_query_information.address.activity_count =
					((TDI_ADDRESS_INFO *)mdl_address)->ActivityCount;
				store_trans_addr(&event->tdi_query_information.address.addr,
						&((TDI_ADDRESS_INFO *)mdl_address)->Address);
				break;
			case TDI_QUERY_CONNECTION_INFO:
				RtlCopyMemory(&event->tdi_query_information.connection,
						mdl_address, sizeof(TDI_CONNECTION_INFO));
				break;
			}
		}
		// TODO: else?
		break;
	}
	default:
		event_buffer_cancel_add(event);
		DbgPrint("tdimon %d:%d f=0x%x ->0x%x\n",
				context->minor_function,
				context->file_object,
				irp->IoStatus.Status);
		goto out;
	}

	event_buffer_finish_add(event);

out:
	if ((NT_SUCCESS(irp->IoStatus.Status) && (context->orig_control & SL_INVOKE_ON_SUCCESS)) ||
			(!NT_SUCCESS(irp->IoStatus.Status) && (context->orig_control & SL_INVOKE_ON_ERROR)) ||
			(irp->Cancel && (context->orig_control & SL_INVOKE_ON_CANCEL))) {
		status = context->orig_cr(device_object, irp, context->orig_context);
	} else {
		status = STATUS_SUCCESS;
	}
	ExFreeToNPagedLookasideList(&context_list, context);
	return status;
}

static PDRIVER_DISPATCH orig_mj_idc;
static NTSTATUS tdimon_mj_idc (DEVICE_OBJECT *device_object, IRP *irp)
{
	IO_STACK_LOCATION *irp_sp = IoGetCurrentIrpStackLocation(irp);
	struct tdimon_context *context;

	if (ESCAPE_CONDITION)
		goto out;

//	DbgPrint("IDC pid=%d, minor=%d\n", (int)PsGetCurrentProcessId(), irp_sp->MinorFunction);
//
	context = (struct tdimon_context *)ExAllocateFromNPagedLookasideList(&context_list);
	if (context == NULL)
		goto out;

	context->minor_function = irp_sp->MinorFunction;
	RtlCopyMemory(context->parameters, &irp_sp->Parameters, 16);
	context->file_object = irp_sp->FileObject;
	context->orig_cr = irp_sp->CompletionRoutine;
	context->orig_context = irp_sp->Context;
	context->orig_control = irp_sp->Control;
	context->time_pre = get_timestamp();
	context->pid = (unsigned long)PsGetCurrentProcessId();
	context->tid = (unsigned long)PsGetCurrentThreadId();
	irp_sp->CompletionRoutine = tdimon_idc_cr;
	irp_sp->Context = context;
	irp_sp->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;

	if (irp_sp->MinorFunction == TDI_SET_EVENT_HANDLER &&
			((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventType < NUM_EVENTS &&
			tdimon_event_handlers[((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventType] != NULL) {
		struct foht_entry *entry;
		int type = ((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventType;

		foht_lock();
		entry = foht_get(irp_sp->FileObject);
		if (((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventHandler == NULL) {
			if (entry == NULL) {
				// do nothing
			} else {
				entry->orig_handler[type] = NULL;
				entry->orig_context[type] = NULL;
			}
		} else {
			if (entry == NULL) {
				// create an entry
				entry = foht_allocate();
				ASSERT(entry != NULL);
				RtlZeroMemory(entry->orig_handler, sizeof(void *) * NUM_EVENTS);
				entry->device_object = irp_sp->DeviceObject;
				entry->file_object = irp_sp->FileObject;
				entry->pid = (unsigned long)PsGetCurrentProcessId();
				entry->tid = (unsigned long)PsGetCurrentThreadId();
				foht_add(entry);
			}
			entry->orig_handler[type] = ((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventHandler;
			entry->orig_context[type] = ((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventContext;
			((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventHandler = tdimon_event_handlers[type];
			((TDI_REQUEST_KERNEL_SET_EVENT *)&irp_sp->Parameters)->EventContext = entry;
		}
		foht_unlock();
	}
out:
	return orig_mj_idc(device_object, irp);
}

static PDRIVER_DISPATCH orig_mj_cleanup;
static NTSTATUS tdimon_mj_cleanup (DEVICE_OBJECT *device_object, IRP *irp)
{
	FILE_OBJECT *file_object = IoGetCurrentIrpStackLocation(irp)->FileObject;
	struct foht_entry *entry;
	NTSTATUS status;
	struct event *event;
	LARGE_INTEGER time_pre, time_post;

	foht_lock();
	entry = foht_get(file_object);
	if (entry != NULL)
		foht_remove(entry);
	foht_unlock();
	if (entry != NULL)
		foht_free(entry);

	time_pre = get_timestamp();
	status = orig_mj_cleanup(device_object, irp);
	time_post = get_timestamp();

	if (ESCAPE_CONDITION)
		return status;

	if ((event = event_buffer_start_add()) != NULL) {
		event->type = ET_TDI_CLEANUP;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_general.file_object = file_object;
		event_buffer_finish_add(event);
	}

	return status;
}

static PDRIVER_DISPATCH orig_mj_close;
static NTSTATUS tdimon_mj_close (DEVICE_OBJECT *device_object, IRP *irp)
{
	FILE_OBJECT *file_object = IoGetCurrentIrpStackLocation(irp)->FileObject;
	NTSTATUS status;
	struct event *event;
	LARGE_INTEGER time_pre, time_post;

	time_pre = get_timestamp();
	status = orig_mj_close(device_object, irp);
	time_post = get_timestamp();

	if (ESCAPE_CONDITION)
		return status;

	if ((event = event_buffer_start_add()) != NULL) {
		event->type = ET_TDI_CLOSE;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_general.file_object = file_object;
		event_buffer_finish_add(event);
	}

	return status;
}

static PDRIVER_DISPATCH orig_mj_create;
static NTSTATUS tdimon_mj_create (DEVICE_OBJECT *device_object, IRP *irp)
{
	IO_STACK_LOCATION *irp_sp = IoGetCurrentIrpStackLocation(irp);
	FILE_FULL_EA_INFORMATION *ea;
	NTSTATUS status;
	struct event *event;
	FILE_OBJECT *file_object = irp_sp->FileObject;
	int type;
	struct tdi_transport_address addr;
	LARGE_INTEGER time_pre, time_post;

	if (ESCAPE_CONDITION)
		return orig_mj_create(device_object, irp);

	ea = (FILE_FULL_EA_INFORMATION *)irp->AssociatedIrp.SystemBuffer;
	if (irp_sp->Parameters.Create.EaLength == 0 || ea == NULL) {
		type = 1;
	} else if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH &&
			memcmp(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0) {
		type = 2;
		store_trans_addr(&addr, (TRANSPORT_ADDRESS *)(ea->EaName + ea->EaNameLength + 1));
	} else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&
			memcmp(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == 0) {
		type = 3;
	}

	time_pre = get_timestamp();
	status = orig_mj_create(device_object, irp);
	time_post = get_timestamp();

	if ((event = event_buffer_start_add()) != NULL) {
		event->type = ET_TDI_CREATE;
		event->status = status;
		event->time_pre = time_pre;
		event->time_post = time_post;
		event->path_length = 0;
		event->path[0] = 0;
		event->tdi_create.file_object = file_object;
		event->tdi_create.type = type;
		if (type == 2)
			RtlCopyMemory(&event->tdi_create.addr, &addr, sizeof(struct tdi_transport_address));
		event_buffer_finish_add(event);
	}

	return status;
}

static NTSTATUS hook_tdi (int is_hooking)
{
	NTSTATUS status;
	UNICODE_STRING str;
	DRIVER_OBJECT *tdi_object;

	RtlInitUnicodeString(&str, L"\\Driver\\Tcpip");
	status = ObReferenceObjectByName(&str,
			OBJ_CASE_INSENSITIVE,
			NULL,
			0,
			IoDriverObjectType,
			KernelMode,
			NULL,
			&tdi_object);
	if (status != STATUS_SUCCESS)
		return status;
	if (is_hooking) {
		orig_mj_idc = tdi_object->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
		tdi_object->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = tdimon_mj_idc;
		orig_mj_cleanup = tdi_object->MajorFunction[IRP_MJ_CLEANUP];
		tdi_object->MajorFunction[IRP_MJ_CLEANUP] = tdimon_mj_cleanup;
		orig_mj_close = tdi_object->MajorFunction[IRP_MJ_CLOSE];
		tdi_object->MajorFunction[IRP_MJ_CLOSE] = tdimon_mj_close;
		orig_mj_create = tdi_object->MajorFunction[IRP_MJ_CREATE];
		tdi_object->MajorFunction[IRP_MJ_CREATE] = tdimon_mj_create;
	} else {
		tdi_object->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = orig_mj_idc;
		tdi_object->MajorFunction[IRP_MJ_CLEANUP] = orig_mj_cleanup;
		tdi_object->MajorFunction[IRP_MJ_CLOSE] = orig_mj_close;
		tdi_object->MajorFunction[IRP_MJ_CREATE] = orig_mj_create;
	}
	ObDereferenceObject(tdi_object);
	return status;
}

NTSTATUS tdi_start (void)
{
	foht_free_removed_entries(); // free those removed in previous session.
	return hook_tdi(1);
}

void tdi_stop (void)
{
	hook_tdi(0);
	foht_remove_all();
}

NTSTATUS tdi_init (void)
{
	NTSTATUS status;

	status = foht_init();
	if (status != STATUS_SUCCESS)
		return status;
	ExInitializeNPagedLookasideList(
			&context_list, NULL, NULL, 0,
			sizeof(struct tdimon_context),
			0x43434d54, // TMCC: tdimon completion routine context.
			0);
	return STATUS_SUCCESS;
}

void tdi_fini (void)
{
	ExDeleteNPagedLookasideList(&context_list);
	foht_fini();
}
