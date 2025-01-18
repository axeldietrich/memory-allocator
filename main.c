#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
    #define ALIGNMENT 16
#elif defined(__i386__) || defined(_M_IX86)
    #define ALIGNMENT 8
#else
    #define ALIGNMENT 8
#endif

#define HEAP_SIZE 1024 * 1024

#ifdef _WIN32
  #include <windows.h>

  #define OS_MAP_FAILED NULL

  #define OS_ALLOC(size) \
  VirtualAlloc(NULL, (size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)

  #define OS_FREE(ptr, size) \
  VirtualFree((ptr), 0, MEM_RELEASE)

#else
  #include <sys/mman.h>
  #include <unistd.h>
  #include <errno.h>

  #define OS_MAP_FAILED MAP_FAILED

  #define OS_ALLOC(size) \
  mmap(NULL, (size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

  #define OS_FREE(ptr, size) \
  munmap((ptr), (size))

#endif

typedef struct MemoryBlock {
    size_t size;
    int is_free;
    struct MemoryBlock *next;
    struct MemoryBlock *free_next;
    void *payload;
} MemoryBlock;

MemoryBlock *main_pointer;
MemoryBlock *free_list_head;
size_t heap_size = HEAP_SIZE;
void *heap_end;

int initialize() {
    printf("Initializing heap of size %llu\n", heap_size);
    main_pointer = OS_ALLOC(heap_size);
    if (main_pointer == NULL) {
        return 1;
    }
    free_list_head = main_pointer;
    heap_end = (char*)main_pointer + heap_size;

    main_pointer->is_free = 1;
    main_pointer->size = HEAP_SIZE - sizeof(MemoryBlock);
    main_pointer->next = NULL;
    main_pointer->free_next = NULL;


    return 0;
}

void* my_malloc(const size_t size) {
    if (size == 0 || main_pointer == NULL) {
        return NULL;
    }
    MemoryBlock *prev = NULL;
    MemoryBlock *current = free_list_head;
    while (current != NULL) {
        if (current->size >= size) {
            // Align payload and calculate remaining space before next block to ensure that the padding
            // didn't leave the block with less space than  requested
            const uintptr_t aligned_payload = ((uintptr_t)current + sizeof(MemoryBlock) + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
            const size_t wasted_space = aligned_payload - (uintptr_t)current - sizeof(MemoryBlock);
            const size_t remaining_space = current->size - wasted_space;

            if (remaining_space < size) {
                prev = current;
                current = current->free_next;
                continue;
            }
            // Not enough memory left on heap for another metadata + space, therefore we allocate the whole remaining space
            // to avoid fragmentation
            if (remaining_space <= size + sizeof(MemoryBlock)) {
                current->is_free = 0;
                current->payload = (void*)aligned_payload;
                if (prev == NULL) {
                    free_list_head = current->free_next;
                } else {
                    prev->free_next = current->free_next;
                }
                current->free_next = NULL;
                return (void*)aligned_payload;
            }

            // Splitting blocks logic
            MemoryBlock *new_block = (MemoryBlock*)((char*)aligned_payload + size);
            if ((char*)&new_block + sizeof(MemoryBlock) > heap_end) {
                return NULL;
            }
            new_block->size = current->size - size - sizeof(MemoryBlock) - wasted_space;
            new_block->is_free = 1;
            new_block->free_next = current->free_next;
            new_block->next = current->next;
            current->size = size;
            current->is_free = 0;
            current->payload = (void*)aligned_payload;
            current->free_next = NULL;
            current->next = new_block;
            if (prev == NULL) {
                free_list_head = new_block;
            } else {
                prev->free_next = new_block;
            }
            return (void*)aligned_payload;
        }

        prev = current;
        current = current->free_next;
    }

    return NULL;
}

int my_free(void* ptr) {
    if (ptr == NULL) {
        return 1;
    }
    if ((uintptr_t)ptr < (uintptr_t)main_pointer || (uintptr_t)ptr >= (uintptr_t)heap_end) {
        return 1;
    }
    MemoryBlock *current = main_pointer;
    MemoryBlock *prev = NULL;
    MemoryBlock *last_free_block = NULL;
    while (current != NULL) {
        if (current->payload == ptr) {
            current->is_free = 1;
            if (prev != NULL && prev == last_free_block) {
                prev->size += (uintptr_t)current->payload - (uintptr_t)current + current->size;
                if (current->next != NULL && current->next->is_free) {
                    prev->size += current->next->size + sizeof(MemoryBlock);
                    prev->next = current->next->next;
                    prev->free_next = current->next->free_next;
                    current->payload = NULL;
                    current->next = NULL;
                    current->free_next = NULL;
                } else {
                    prev->next = current->next;
                }
            } else if (current->next != NULL && current->next->is_free) {
                current->size += (uintptr_t)current->payload - (uintptr_t)current + current->next->size + sizeof(MemoryBlock);
                current->free_next = current->next->free_next;
                current->next = current->next->next;
                current->payload = NULL;
                if (last_free_block != NULL) {
                    last_free_block->free_next = current;
                } else {
                    free_list_head = current;
                }
            } else {
                current->size += (uintptr_t)current->payload - (uintptr_t)current;
                current->payload = NULL;
                if (last_free_block != NULL) {
                    current->free_next = last_free_block->free_next;
                    last_free_block->free_next = current;
                } else {
                    current->free_next = free_list_head;
                    free_list_head = current;
                }
            }
            return 0;
        }
        if (current->is_free) {
            last_free_block = current;
        }
        prev = current;
        current = current->next;
    }
    return 1;
}

int main() {
   // 1) Initialize
    printf("Test 1: Initialize\n");
    int init_result = initialize();
    assert(init_result == 0);
    printf("Heap initialized successfully.\n");

    // 2) Allocate small block
    printf("Test 2: Allocate small block\n");
    char *ptr1 = (char*)my_malloc(16);
    assert(ptr1 != NULL);
    printf("Allocated small block at %p\n", (void*)ptr1);

    // 3) Allocate second block
    printf("Test 3: Allocate second block\n");
    char *ptr2 = (char*)my_malloc(32);
    assert(ptr2 != NULL);
    printf("Allocated second block at %p\n", (void*)ptr2);

    // 4) Write and read data in the allocated block
    printf("Test 4: Write data and read it back\n");
    strcpy(ptr1, "Hello, Memory!");
    assert(strcmp(ptr1, "Hello, Memory!") == 0);
    printf("Data in ptr1: %s\n", ptr1);

    // 5) Free the first block
    printf("Test 5: Free the first block\n");
    assert(my_free(ptr1) == 0);
    printf("Freed first block at %p\n", (void*)ptr1);

    // 6) Allocate a larger block that should reuse or coalesce space
    printf("Test 6: Allocate a larger block after freeing\n");
    char *ptr3 = (char*)my_malloc(64);
    assert(ptr3 != NULL);
    printf("Allocated third block at %p\n", (void*)ptr3);

    // 7) Free the second block
    printf("Test 7: Free the second block\n");
    assert(my_free(ptr2) == 0);
    printf("Freed second block at %p\n", (void*)ptr2);

    // 8) Free the third block
    printf("Test 8: Free the third block\n");
    assert(my_free(ptr3) == 0);
    printf("Freed third block at %p\n", (void*)ptr3);

    // 9) Try allocating a very large block (close to HEAP_SIZE)
    printf("Test 9: Allocate near-max block\n");
    char *ptr4 = (char*)my_malloc(HEAP_SIZE - 128);
    if (ptr4 == NULL) {
        printf("Allocation for near-max block failed, as expected or not.\n");
    } else {
        printf("Allocated near-max block at %p\n", (void*)ptr4);
        // Free it if successfully allocated
        assert(my_free(ptr4) == 0);
        printf("Freed near-max block.\n");
    }

    // 10) Edge Cases
    // a) Allocate zero bytes -> should return NULL
    printf("Test 10a: Allocate 0 bytes\n");
    void* ptr_zero = my_malloc(0);
    assert(ptr_zero == NULL);
    printf("Allocation of 0 bytes returned NULL as expected.\n");

    // b) Free NULL pointer
    printf("Test 10b: Free NULL pointer\n");
    assert(my_free(NULL) == 1);
    printf("Freeing NULL returned error code as expected.\n");

    // c) Free invalid pointer (out of range)
    printf("Test 10c: Free invalid pointer\n");
    char dummy_stack_variable = 42;
    assert(my_free(&dummy_stack_variable) == 1);
    printf("Freeing invalid pointer returned error code as expected.\n");

    // If we reach here, all asserts passed
    printf("\nAll tests passed successfully.\n");
    return 0;
    OS_FREE(main_pointer, HEAP_SIZE);
}
