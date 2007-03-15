#include <ntddk.h>
#include "resmonk.h"

#define FREE_POOL_SIZE 16
#define LRU_SIZE       4096
#define HASHTABLE_SIZE 2007
#define TAG 0x4d535257l //WRSM

#define HASH_HANDLE(pid,handle) (((unsigned int)(pid)) * ((unsigned int)(handle)) % HASHTABLE_SIZE)

static LIST_ENTRY free_pool_head;
static int free_pool_size;
static LIST_ENTRY lru_head;
static int lru_size;
static LIST_ENTRY hashtable[HASHTABLE_SIZE];
static FAST_MUTEX mutex;

struct htable_entry *htable_allocate_entry (void)
{
	struct htable_entry *retval;

	ExAcquireFastMutex(&mutex);
	if (free_pool_size > 0) {
		retval = CONTAINING_RECORD(RemoveHeadList(&free_pool_head), struct htable_entry, list);
		free_pool_size --;
		ASSERT(retval->status == 0);
	} else if (lru_size >= LRU_SIZE) {
		retval = CONTAINING_RECORD(RemoveTailList(&lru_head), struct htable_entry, list);
		lru_size --;
		RemoveEntryList(&retval->ht_list);
		ASSERT(retval->status == 2);
	} else {
		retval = ExAllocatePoolWithTag(PagedPool, sizeof(struct htable_entry), TAG);
	}
	retval->status = 1;
	ExReleaseFastMutex(&mutex);

	return retval;
}

void htable_free_entry (struct htable_entry *entry)
{
	ASSERT(entry);
	ASSERT(entry->status == 1);

	ExAcquireFastMutex(&mutex);
	entry->status = 0;
	if (free_pool_size >= FREE_POOL_SIZE) {
		// let it cool down for a while
		InsertTailList(&free_pool_head, &entry->list);
		ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&free_pool_head), struct htable_entry, list), TAG);
	} else {
		InsertTailList(&free_pool_head, &entry->list);
		free_pool_size ++;
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
	ASSERT(entry->status == 1);

	hashval = HASH_HANDLE(entry->pid, entry->handle);
	entry->status = 2;

	ExAcquireFastMutex(&mutex);
	// remove duplicate key if exists
	for (curr = hashtable[hashval].Flink; curr != &hashtable[hashval]; curr = curr->Flink) {
		struct htable_entry *tofree = CONTAINING_RECORD(curr, struct htable_entry, ht_list);
		if (tofree->pid == entry->pid && tofree->handle == entry->handle) {
			ASSERT(tofree != entry);
			RemoveEntryList(&tofree->list);
			lru_size --;
			RemoveEntryList(&tofree->ht_list);
			tofree->status = 0;
			if (free_pool_size >= FREE_POOL_SIZE) {
				// let it cool down for a while
				InsertTailList(&free_pool_head, &tofree->list);
				ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&free_pool_head), struct htable_entry, list), TAG);
			} else {
				InsertTailList(&free_pool_head, &tofree->list);
				free_pool_size ++;
			}
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
		ASSERT(entry->status == 2);
		RemoveEntryList(&entry->list);
		InsertHeadList(&lru_head, &entry->list);
	}
	ExReleaseFastMutex(&mutex);

	return entry;
}

void htable_remove_entry (struct htable_entry *entry)
{
	ASSERT(entry);
	ASSERT(entry->pid);
	ASSERT(entry->handle);

	ExAcquireFastMutex(&mutex);
	if (entry->status == 2) {
		// remove from LRU
		RemoveEntryList(&entry->list);
		lru_size --;
		// remove from hashtable
		RemoveEntryList(&entry->ht_list);
	}
	ExReleaseFastMutex(&mutex);

	entry->status = 1;
}

void htable_remove_process_entries (unsigned long pid)
{
	LIST_ENTRY *curr;

	ExAcquireFastMutex(&mutex);
	for (curr = lru_head.Flink; curr != &lru_head; ) {
		struct htable_entry *entry = CONTAINING_RECORD(curr, struct htable_entry, list);
		curr = curr->Flink;
		if (entry->pid == pid) {
			ASSERT(entry->status == 2);

			RemoveEntryList(&entry->list);
			lru_size --;
			RemoveEntryList(&entry->ht_list);

			entry->status = 0;
			if (free_pool_size >= FREE_POOL_SIZE) {
				// let it cool down for a while
				InsertTailList(&free_pool_head, &entry->list);
				ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&free_pool_head), struct htable_entry, list), TAG);
			} else {
				InsertTailList(&free_pool_head, &entry->list);
				free_pool_size ++;
			}
		}
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
