#include <ntddk.h>
#include "resmonk.h"

#define FREE_POOL_SIZE 16
#define LRU_SIZE       4096
#define HASHTABLE_SIZE 2007
#define TAG 0x4d535257l //WRSM

#define HASH_HANDLE(pid,handle) ((((unsigned int)(pid) << (unsigned int)16) ^ ((unsigned int)(handle))) % (unsigned int)HASHTABLE_SIZE)

static LIST_ENTRY free_pool_head;
static int free_pool_size;
static LIST_ENTRY lru_head;
static int lru_size;
static LIST_ENTRY hashtable[HASHTABLE_SIZE];
static FAST_MUTEX mutex;

// assume the entry is ADDED; reference_count is already decreased; lock is acquired
static void htable_remove_entry_internal (struct htable_entry *entry)
{
	ASSERT(entry->status == HTES_ADDED);
	ASSERT(entry->reference_count >= 0);

	RemoveEntryList(&entry->list);
	lru_size --;
	RemoveEntryList(&entry->ht_list);

	if (entry->reference_count > 0) {
		entry->status = HTES_FREEING;
	} else {
		if (free_pool_size >= FREE_POOL_SIZE) {
			ExFreePoolWithTag(entry, TAG);
		} else {
			entry->status = HTES_FREED;
			InsertTailList(&free_pool_head, &entry->list);
			free_pool_size ++;
		}
	}
}

struct htable_entry *htable_allocate_entry (void)
{
	struct htable_entry *retval;

	ExAcquireFastMutex(&mutex);
	if (free_pool_size > 0) {
		retval = CONTAINING_RECORD(RemoveHeadList(&free_pool_head), struct htable_entry, list);
		free_pool_size --;
		ASSERT(retval->status == HTES_FREED);
	} else if (lru_size >= LRU_SIZE) {
		LIST_ENTRY *curr;
		// find a least recent used & not currently using entry
		for (curr = lru_head.Blink; curr != &lru_head; curr = curr->Blink) {
			retval = CONTAINING_RECORD(curr, struct htable_entry, list);
			if (retval->reference_count == 0)
				break;
		}
		ASSERT(retval->reference_count == 0);
		ASSERT(retval->status == HTES_ADDED);
		retval = CONTAINING_RECORD(curr, struct htable_entry, list);
		RemoveEntryList(&retval->list);
		lru_size --;
		RemoveEntryList(&retval->ht_list);
	} else {
		retval = ExAllocatePoolWithTag(PagedPool, sizeof(struct htable_entry), TAG);
	}
	ExReleaseFastMutex(&mutex);
	retval->status = HTES_ALLOCATED;

	return retval;
}

struct htable_entry *htable_get_entry (unsigned long pid, HANDLE handle)
{
	unsigned int hashval = HASH_HANDLE(pid, handle);
	struct htable_entry *entry = NULL;
	LIST_ENTRY *curr;

	ExAcquireFastMutex(&mutex);
	for (curr = hashtable[hashval].Flink;
			curr != &hashtable[hashval];
			curr = curr->Flink) {
		entry = CONTAINING_RECORD(curr, struct htable_entry, ht_list);
		if (entry->pid == pid && entry->handle == handle)
			break;
		entry = NULL;
	}
	if (entry != NULL) {
		ASSERT(entry->status == HTES_ADDED);
		ASSERT(entry->reference_count >= 0);
		entry->reference_count ++;
		RemoveEntryList(&entry->list);
		InsertHeadList(&lru_head, &entry->list);
	}
	ExReleaseFastMutex(&mutex);

	return entry;
}

void htable_put_entry (struct htable_entry *entry)
{
	ASSERT(entry);
	ASSERT(entry->status == HTES_ADDED || entry->status == HTES_FREEING);
	ASSERT(entry->reference_count > 0);

	ExAcquireFastMutex(&mutex);
	entry->reference_count --;
	if (entry->reference_count == 0 && entry->status == HTES_FREEING) {
		if (free_pool_size >= FREE_POOL_SIZE) {
			ExFreePoolWithTag(entry, TAG);
		} else {
			entry->status = HTES_FREED;
			InsertTailList(&free_pool_head, &entry->list);
			free_pool_size ++;
		}
	}
	ExReleaseFastMutex(&mutex);
}

void htable_add_entry (struct htable_entry *entry)
{
	unsigned int hashval;
	LIST_ENTRY *curr;

	ASSERT(entry);
	ASSERT(entry->pid);
	ASSERT(entry->handle);
	ASSERT(entry->status == HTES_ALLOCATED);

	entry->status = HTES_ADDED;
	entry->reference_count = 1;
	hashval = HASH_HANDLE(entry->pid, entry->handle);

	ExAcquireFastMutex(&mutex);
	// remove duplicate key if exists
	for (curr = hashtable[hashval].Flink; curr != &hashtable[hashval]; curr = curr->Flink) {
		struct htable_entry *tofree = CONTAINING_RECORD(curr, struct htable_entry, ht_list);
		if (tofree->pid == entry->pid && tofree->handle == entry->handle) {
			ASSERT(tofree != entry);
			ASSERT(tofree->status == HTES_ADDED);
			htable_remove_entry_internal(tofree);
			break;
		}
	}
	// add to LRU
	InsertHeadList(&lru_head, &entry->list);
	lru_size ++;
	// add to hashtable
	InsertHeadList(&hashtable[hashval], &entry->ht_list);
	ExReleaseFastMutex(&mutex);
}

void htable_remove_entry (struct htable_entry *entry)
{
	ASSERT(entry);
	ASSERT(entry->status == HTES_ADDED || entry->status == HTES_FREEING);
	ASSERT(entry->reference_count > 0);

	ExAcquireFastMutex(&mutex);
	entry->reference_count --;
	if (entry->status == HTES_ADDED) {
		RemoveEntryList(&entry->list);
		lru_size --;
		RemoveEntryList(&entry->ht_list);
	}
	if (entry->reference_count > 0) {
		entry->status = HTES_FREEING;
	} else {
		if (free_pool_size >= FREE_POOL_SIZE) {
			ExFreePoolWithTag(entry, TAG);
		} else {
			entry->status = HTES_FREED;
			InsertTailList(&free_pool_head, &entry->list);
			free_pool_size ++;
		}
	}
	ExReleaseFastMutex(&mutex);
}

void htable_remove_process_entries (unsigned long pid)
{
	LIST_ENTRY *curr;

	ExAcquireFastMutex(&mutex);
	for (curr = lru_head.Flink; curr != &lru_head; ) {
		struct htable_entry *entry = CONTAINING_RECORD(curr, struct htable_entry, list);
		curr = curr->Flink;
		if (entry->pid == pid)
			htable_remove_entry_internal(entry);
	}
	ExReleaseFastMutex(&mutex);
}

NTSTATUS handle_table_init (void)
{
	int i;

	InitializeListHead(&free_pool_head);
	free_pool_size = 0;
	InitializeListHead(&lru_head);
	lru_size = 0;
	for (i = 0; i < HASHTABLE_SIZE; i ++)
		InitializeListHead(&hashtable[i]);
	ExInitializeFastMutex(&mutex);

	return STATUS_SUCCESS;
}

NTSTATUS handle_table_start (void)
{
	LIST_ENTRY *list;
	int i;

	// we don't need to touch the free_pool

	for (list = lru_head.Flink; list != &lru_head; ) {
		LIST_ENTRY *next = list->Flink;
		ExFreePoolWithTag(CONTAINING_RECORD(list, struct htable_entry, list), TAG);
		list = next;
	}
	InitializeListHead(&lru_head);
	lru_size = 0;

	for (i = 0; i < HASHTABLE_SIZE; i ++)
		InitializeListHead(&hashtable[i]);

	return STATUS_SUCCESS;
}

void handle_table_stop (void)
{
	// do nothing here
}

void handle_table_fini (void)
{
	LIST_ENTRY *list;

	for (list = free_pool_head.Flink; list != &free_pool_head; ) {
		LIST_ENTRY *next = list->Flink;
		ExFreePoolWithTag(CONTAINING_RECORD(list, struct htable_entry, list), TAG);
		list = next;
	}
	InitializeListHead(&free_pool_head);
	free_pool_size = 0;

	for (list = lru_head.Flink; list != &lru_head; ) {
		LIST_ENTRY *next = list->Flink;
		ExFreePoolWithTag(CONTAINING_RECORD(list, struct htable_entry, list), TAG);
		list = next;
	}
	InitializeListHead(&lru_head);
	lru_size = 0;

	// forget about the hashtable
}
