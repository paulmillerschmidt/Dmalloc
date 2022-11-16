#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <math.h>

#define HEADER_SIZE sizeof(struct header_t)
#define FOOTER_SIZE sizeof(struct footer_t)
#define CANARY -123456
#define PRESENT_NUM -654321
#define CANARY_SIZE sizeof(int)
#define FL_ARR_SIZE 20

unsigned long long malloc_nactive;         // # active allocations
unsigned long long malloc_active_size;     // # bytes in active allocations
unsigned long long malloc_ntotal;          // # total allocations
unsigned long long malloc_total_size;      // # bytes in total allocations
unsigned long long malloc_nfail;           // # failed allocation attempts
unsigned long long malloc_fail_size;       // # bytes in failed alloc attempts
unsigned long long malloc_samples_size;
uintptr_t malloc_heap_min = (long unsigned int) 4294967294;                 // smallest allocated addr
uintptr_t malloc_heap_max = 0;    

struct header_t {
    uintptr_t addr;
    int size;
    bool freed;
    int underflow;
    const char* file;
    long line;
    int present;
};


struct footer_t {
    int overflow;
};

//linked list
struct metadata_Node {
    header_t *metadata;
    struct metadata_Node* next;
    struct metadata_Node* prev;
};

//make the head and the tail globals
struct metadata_Node* head = NULL;
struct metadata_Node* tail = NULL;
bool init = false;

struct metadata_Node *create_node(header_t *data) {
    struct metadata_Node* result = (struct metadata_Node*) malloc(sizeof(struct metadata_Node));
    result->metadata = data;
    result->prev = NULL;
    result->next = NULL;
    return result;
    
}

struct metadata_Node *create_node() {
    struct metadata_Node* result = (struct metadata_Node*) malloc(sizeof(struct metadata_Node));
    result->prev = NULL;
    result->next = NULL;
    return result;
}

void init_list() {
    head = create_node();
    tail = create_node();
    head->next = tail;
    tail->prev = head;
}

void add_header(header_t *metadata) {
    struct metadata_Node *node = create_node(metadata);

    if (head == NULL) {
        init_list();
    }

    head->next->prev = node;
    node->next = head->next;
    node->prev = head;
    head->next = node;

}

void remove_node(metadata_Node *node) {
        node->prev->next = node->next;
        node->next->prev = node->prev;
}

void remove_header(header_t *h) {
    int active = (int) malloc_nactive;
    struct metadata_Node* current = head->next;

    for (int i = 1; i < active + 1; i++) {
        if(current->metadata == h) {remove_node(current);}
        current = current->next;

    }
}

metadata_Node* get_node(header_t *h) {
    int active = (int) malloc_nactive;
    struct metadata_Node* current = head->next;

    for (int i = 1; i < active + 1; i++) {
        if(current->metadata == h) {return current;}
        current = current->next;

    }
    return nullptr;
}

header_t *within_block(void* p) {
    struct metadata_Node* current = head->next;
    uintptr_t ptr_addr = reinterpret_cast<uintptr_t>(p);

    for (int i = 1; i < (int) malloc_nactive + 1; i++) {
        uintptr_t block_end = current->metadata->addr + (uintptr_t) current->metadata->size + CANARY_SIZE;

        if (current->metadata->addr < ptr_addr && ptr_addr < block_end) {       
            return current->metadata;
        } else {
            current = current->next;
        }
    }
    return nullptr;
}

//HEAVY HITTERS
struct file_line_pair_t {
    const char* file;
    long line;
};

struct heavy_hitter_t {
    const char* file;
    long line;
    size_t size;
};

file_line_pair_t *create_file_line_pair(const char* file, long line) {
    file_line_pair_t *result = (struct file_line_pair_t*) malloc(sizeof(struct file_line_pair_t));
    result->file = file;
    result->line = line;
    return result;
}

heavy_hitter_t *create_heavy_hitter(const char* file, long line, size_t size) {
    heavy_hitter_t *result = (struct heavy_hitter_t*) malloc(sizeof(struct heavy_hitter_t));
    result->file = file;
    result->line = line;
    result->size = size;
    return result;
}

//heavy hitter arrays
size_t *elimination_set_arr = (size_t *) malloc (sizeof(size_t) * FL_ARR_SIZE); 
file_line_pair_t* file_line_arr = (struct file_line_pair_t *) malloc (sizeof(struct file_line_pair_t) * FL_ARR_SIZE); 
heavy_hitter_t* heavy_hitter_arr = (struct heavy_hitter_t *) malloc (sizeof(struct heavy_hitter_t) * FL_ARR_SIZE); 
int counter = 0;

bool is_full() {
    return (counter == FL_ARR_SIZE);   
}

void sub_from_arr(size_t min_size) {
    for (int i = 0; i < 5; i++) {
        elimination_set_arr[i] = elimination_set_arr[i] - min_size;
    }
}

int find_min() {
    int curr_min = 2147483646;
    int curr_index = 0;

    for(int i = 0; i < 5; i++) {
        if ((int) elimination_set_arr[i] < curr_min) {
            curr_min = (int) elimination_set_arr[i];
            curr_index = i;
        }
    }
    return curr_index;
}

int get_min_size() {
    int curr_min = 2147483646; 
    for(int i = 0; i < 5; i++) {
        if ((int) elimination_set_arr[i] < curr_min) {
            curr_min = (int) elimination_set_arr[i];
        }
    }
    return curr_min;
}

int cmpfunc(const void *p, const void *q) {
    size_t l = ((struct heavy_hitter_t *)p)->size;
    size_t r = ((struct heavy_hitter_t *)q)->size;

    if (l > r) return -1;
    if (l < r) return 1;
    if (l == r) return 0;
    else return 0;

}

void add_hh_allocation(const char* file, long line, size_t size) {

    for(int i = 0; i < FL_ARR_SIZE; i++) {
        //if its the same file line pair, add to the size
        if (file_line_arr[i].file == file && file_line_arr[i].line == line) {
            elimination_set_arr[i] += size;
            return;
        }
    }

    file_line_pair_t *new_fl_pair = create_file_line_pair(file, line);
    //if its not full, add an element
    if (!is_full()) {
        // printf("got here\n");
        file_line_arr[counter] = *new_fl_pair;
        elimination_set_arr[counter] = size;
        counter++;
    } 
    //if its not full, do stream and bags 
    else {
        // printf("got here");   
        int min_index = find_min();
        //if the fl pair is grater than the min, add, if not, dont 
        if (size > elimination_set_arr[min_index]) {
            file_line_arr[min_index] = *new_fl_pair;
            elimination_set_arr[min_index] = size;
        // sub_from_arr(get_min_size());
        }
    }
}

void* dmalloc_malloc(size_t sz, const char* file, long line) {

    void* ptr = base_malloc(sz +  HEADER_SIZE + FOOTER_SIZE);

    //if it's null return 0
    if (ptr == NULL) {
        malloc_nfail = malloc_nfail + 1;
        malloc_fail_size = malloc_fail_size + sz;
        return NULL;
    }

    //calculate every address
    uintptr_t header_addr = reinterpret_cast<uintptr_t>(ptr);
    uintptr_t payload_addr = reinterpret_cast<uintptr_t>(ptr) + HEADER_SIZE;
    uintptr_t footer_addr = reinterpret_cast<uintptr_t>(ptr) + HEADER_SIZE + sz; 

    header_t *header = reinterpret_cast<header_t*>(header_addr);
    footer_t *footer = reinterpret_cast<footer_t*>(footer_addr);

    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    //check size, if its too large fail
    if (sz > (size_t) -1 - HEADER_SIZE - FOOTER_SIZE) {
        malloc_nfail = malloc_nfail + 1;
        malloc_fail_size = malloc_fail_size + sz;
        return NULL;
    }

    //need to do comparions before actual assignment
    if ((payload_addr + sz) >= malloc_heap_max) {
        malloc_heap_max = (payload_addr + sz);
    }

    if (payload_addr <= malloc_heap_min) {
        malloc_heap_min = payload_addr;
    }

    //update the stats
    malloc_active_size = malloc_active_size + sz;
    malloc_total_size = malloc_total_size + sz;
    malloc_nactive = malloc_nactive + 1;
    malloc_ntotal = malloc_ntotal + 1;

    
    //set header info
    header->size = sz;
    header->freed = false;
    header->underflow = CANARY;
    header->file = file;
    header->line = line;
    header->addr = payload_addr;
    header->present = PRESENT_NUM;
    //add the header to the linked list
    add_header(header);

    //set footer info
    footer->overflow = CANARY;

    //assign hh allocation, sample 50% 
    if ((rand() % 100) >= 50) {
        add_hh_allocation(file, line, sz);
        malloc_samples_size += sz;
    }

    return reinterpret_cast<void*>(payload_addr);
}

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    //if its null
    if (ptr == NULL) {
        return; 
    }
    //check if it is in the heap
    bool within_heap = (reinterpret_cast<uintptr_t>(ptr) >= malloc_heap_min) && (reinterpret_cast<uintptr_t>(ptr) <= malloc_heap_max);
    if (!within_heap) {
        fprintf(stderr, "MEMORY BUG %s %ld: invalid free of pointer %p, not in heap", file, line, ptr);
        exit(1);
    }
    
    //set metadata addr and metadata 
    uintptr_t metadata_addr = (reinterpret_cast<uintptr_t>(ptr)) - HEADER_SIZE;
    header_t* metadata = reinterpret_cast<header_t*>(metadata_addr);
    
    //if its been freed, fail
    if (metadata->freed == true) {
        fprintf(stderr, "MEMORY BUG %s %ld: invalid free of pointer %p, double free", file, line, ptr);
        exit(1);
    }

    //if the metadata is null or if the metadata node is null, fail 
    if (reinterpret_cast<int*>(metadata)[0] == '\0' || get_node(metadata) == nullptr) {
        
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        header_t *result = within_block(ptr);

        if (result != nullptr) {
            fprintf(stderr, "  %s:%ld: %p is %ld bytes inside a %d byte region allocated here\n", result->file, result->line, ptr, (uintptr_t) ptr - result->addr, result->size);
          } 
        exit(1);

    }

    //check overflow and underflow 
    footer_t* footer = (footer_t*) (metadata_addr + HEADER_SIZE + metadata->size);
    //check canaries 
    if (metadata->underflow != CANARY) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p", file, line, ptr);
        exit(1);
    }
    if (footer->overflow != CANARY) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p", file, line, ptr);
        exit(1);
    }

    //true because we freed
    metadata->freed = true;
    //remove the header
    remove_header(metadata);

    //update the stats
    malloc_active_size = malloc_active_size - metadata->size;
    malloc_nactive = malloc_nactive - 1;    

    base_free((void*) metadata_addr);

}

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Your code here (to fix test014).
    if (nmemb > ((size_t) - 1)/sz) {        
        malloc_nfail = malloc_nfail + 1;
        malloc_fail_size = malloc_fail_size + sz;
        return NULL;
    }

    void* ptr = dmalloc_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    // Your code here.
    stats->nactive = malloc_nactive;         
    stats->active_size =  malloc_active_size;
    stats->ntotal = malloc_ntotal;         
    stats->total_size = malloc_total_size;      
    stats->nfail = malloc_nfail;           
    stats->fail_size = malloc_fail_size;             
    stats->heap_max = malloc_heap_max;     
    stats->heap_min = malloc_heap_min; 

}


void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

void dmalloc_print_leak_report() {
    // Your code here.
     struct metadata_Node* current = head->next;
     header_t *metadata;

    for (int i = 1; i < (int) malloc_nactive + 1; i++) {

        metadata = current->metadata;
        printf("LEAK CHECK: %s:%ld: allocated object %p with size %d\n", metadata->file, metadata->line, (void *) metadata->addr, metadata->size);
        current = current->next;

    }


}

void dmalloc_print_heavy_hitter_report() {

    //add to hh arr
    for (int i = 0; i < FL_ARR_SIZE; i++) {
        heavy_hitter_t *new_hh = create_heavy_hitter(file_line_arr[i].file, file_line_arr[i].line, elimination_set_arr[i]);
        heavy_hitter_arr[i] = *new_hh;
    }

    //sort the list
    qsort(heavy_hitter_arr, FL_ARR_SIZE, sizeof(heavy_hitter_t), size_comparator);

    //print hh info
    for (int i = 0; i < FL_ARR_SIZE; i++) {
        float perc = ((float) heavy_hitter_arr[i].size / (float) malloc_samples_size) * 100;
        float alloc_total_size = (float) heavy_hitter_arr[i].size * 2.0;
        //if the percentage is large enough, print it
        if (perc > 10.0) {
            printf("HEAVY HITTER: %s:%ld: %ld bytes (~%.2f%%)\n", heavy_hitter_arr[i].file, heavy_hitter_arr[i].line, (size_t) alloc_total_size, perc);
        }
    }


}
