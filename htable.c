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
		unsigned int hashval;

		retval = CONTAINING_RECORD(lru_head.Blink, struct htable_entry, lru);
		// remove from LRU
		RemoveEntryList(&retval->lru);
		lru_size --;
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

	retval->name_length = 0;
	return retval;
}

void htable_free_entry (struct htable_entry *entry)
{
	ASSERT(entry);
	ASSERT(!entry->name_length);

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

void htable_add_entry (struct htable_entry *entry)
{
	unsigned int hashval;
	struct htable_entry *curr;

	ASSERT(entry);
	ASSERT(entry->pid);
	ASSERT(entry->handle);
	ASSERT(entry->name_length);

	hashval = HASH_HANDLE(entry->pid, entry->handle);

	ExAcquireFastMutex(&mutex);
	// add to LRU
	InsertHeadList(&lru_head, &entry->lru);
	lru_size ++;
	// add to hashtable
	entry->next = hashtable[hashval];
	hashtable[hashval] = entry;
	// remove duplicate key if exists
	for (curr = entry; curr->next != NULL; curr = curr->next) {
		if (curr->next->pid == entry->pid && curr->next->handle == entry->handle) {
			struct htable_entry *tofree = curr->next;
			ASSERT(tofree != entry);

			RemoveEntryList(&tofree->lru);
			lru_size --;
			curr->next = tofree->next;

			if (free_pool_size >= FREE_POOL_SIZE) {
				ExFreePoolWithTag(tofree, TAG);
			} else {
				tofree->next = free_pool;
				free_pool = tofree;
				free_pool_size ++;
			}

			break;
		}
	}
	ExReleaseFastMutex(&mutex);
}

struct htable_entry *htable_get_entry (unsigned long pid, HANDLE handle)
{
	struct htable_entry *entry;

	ExAcquireFastMutex(&mutex);
	for (entry = hashtable[HASH_HANDLE(pid, handle)];
			entry != NULL && (entry->pid != pid || entry->handle != handle);
			entry = entry->next)
		;
	if (entry != NULL) {
		RemoveEntryList(&entry->lru);
		InsertHeadList(&lru_head, &entry->lru);
	}
	ExReleaseFastMutex(&mutex);

	return entry;
}

void htable_remove_entry (struct htable_entry *entry)
{
	struct htable_entry *curr;
	unsigned int hashval;

	ASSERT(entry);
	ASSERT(entry->pid);
	ASSERT(entry->handle);
	ASSERT(entry->name_length);

	hashval = HASH_HANDLE(entry->pid, entry->handle);

	ExAcquireFastMutex(&mutex);
	// remove from LRU
	RemoveEntryList(&entry->lru);
	lru_size --;
	// remove from hashtable
	curr = hashtable[hashval];
	ASSERT(curr);
	if (curr->next == NULL) {
		ASSERT(curr == entry);
		hashtable[hashval] = NULL;
	} else {
		DbgPrint("hashval=%d, entry=%x, entry->pid=%x, entry->handle=%x\n", hashval, entry, entry->pid, entry->handle);
		while (curr->next != NULL && curr->next != entry) {
			DbgPrint("curr->next=%x, curr->next->pid=%x, curr->next->handle=%x\n", curr->next, curr->next->pid, curr->next->handle);
			curr = curr->next;
		}
		ASSERT(curr->next != NULL);
		curr->next = entry->next;
	}
	ExReleaseFastMutex(&mutex);

	entry->name_length = 0;
}

void htable_remove_process_entries (unsigned long pid)
{
	unsigned int hashval;

	ExAcquireFastMutex(&mutex);
	for (hashval = 0; hashval < HASHTABLE_SIZE; hashval ++) {
		struct htable_entry *entry = hashtable[hashval];
		while (entry != NULL && entry->pid == pid) {
			RemoveEntryList(&entry->lru);
			lru_size --;
			hashtable[hashval] = entry->next;
			if (free_pool_size >= FREE_POOL_SIZE) {
				ExFreePoolWithTag(entry, TAG);
			} else {
				entry->next = free_pool;
				free_pool = entry;
				free_pool_size ++;
			}
			entry = hashtable[hashval];
		}
		if (entry == NULL)
			continue;
		while (entry->next != NULL) {
			if (entry->next->pid == pid) {
				struct htable_entry *tofree = entry->next;
				RemoveEntryList(&tofree->lru);
				lru_size --;
				entry->next = tofree->next;

				if (free_pool_size >= FREE_POOL_SIZE) {
					ExFreePoolWithTag(tofree, TAG);
				} else {
					tofree->next = free_pool;
					free_pool = tofree;
					free_pool_size ++;
				}
			} else {
				entry = entry->next;
			}
		}
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
	lru_size = 0;

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
