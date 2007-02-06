#include <ntddk.h>
#include "resmonk.h"

#define FREE_POOL_SIZE 16
#define LRU_SIZE       4096
#define HASHTABLE_SIZE 2007
#define TAG 0x4d535257l //WRSM

#define HASH_HANDLE(pid,handle) (((unsigned int)(pid)) * ((unsigned int)(handle)) % HASHTABLE_SIZE)

static struct htable_entry *free_pool;
static int free_pool_size;
static LIST_ENTRY lru_head;
static int lru_size;
static struct htable_entry *hashtable[HASHTABLE_SIZE];
static FAST_MUTEX mutex;

struct htable_entry *htable_allocate_entry (void)
{
	struct htable_entry *retval;

	ExAcquireFastMutex(&mutex);
	if (free_pool != NULL) {
		retval = free_pool;
		free_pool = retval->next;
		free_pool_size --;
	} else if (lru_size >= LRU_SIZE) {
		struct htable_entry *entry;
		struct htable_entry *retval = CONTAINING_RECORD(lru_head.Blink, struct htable_entry, lru);
		unsigned int hashval;
		// remove from LRU
		RemoveEntryList(&retval->lru);
		// remove from hashtable
		hashval = HASH_HANDLE(retval->pid, retval->handle);
		entry = hashtable[hashval];
		ASSERT(entry);
		if (entry->next == NULL) {
			ASSERT(entry == retval);
			hashtable[hashval] = NULL;
		} else {
			while (entry->next != NULL && entry->next != retval)
				entry = entry->next;
			ASSERT(entry->next == retval);
			entry->next = retval->next;
		}
	} else {
		retval = ExAllocatePoolWithTag(PagedPool, sizeof(struct htable_entry), TAG);
	}
	ExReleaseFastMutex(&mutex);

	return retval;
}

void htable_free_entry (struct htable_entry *entry)
{
	ExAcquireFastMutex(&mutex);
	if (free_pool_size >= FREE_POOL_SIZE) {
		ExFreePoolWithTag(entry, TAG);
	} else {
		entry->next = free_pool;
		free_pool = entry;
		free_pool_size ++;
	}
	ExReleaseFastMutex(&mutex);
}

NTSTATUS handle_table_init (void)
{
	ExInitializeFastMutex(&mutex);
	free_pool = NULL;
	free_pool_size = 0;
	RtlZeroMemory(hashtable, sizeof(hashtable));
	InitializeListHead(&lru_head);

	return STATUS_SUCCESS;
}

void handle_table_fini (void)
{
	struct htable_entry *entry;
	LIST_ENTRY *list;

	ExAcquireFastMutex(&mutex);
	for (entry = free_pool; entry != NULL; ) {
		struct htable_entry *next = entry->next;
		ExFreePoolWithTag(entry, TAG);
		entry = next;
	}
	free_pool = NULL;
	free_pool_size = 0;

	for (list = lru_head.Flink; list != &lru_head; ) {
		LIST_ENTRY *next = list->Flink;
		ExFreePoolWithTag(CONTAINING_RECORD(list, struct htable_entry, lru), TAG);
		list = next;
	}
	InitializeListHead(&lru_head);
	ExReleaseFastMutex(&mutex);
}
