#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

#define METADATA_START 0
#define DEFAULT_MEMORY_SIZE (4 * 1024 * 1024)  // 4MB
#define DATA_START (sizeof(uint32_t))
#define MAX_FILES 256
#define MAX_TASKS 16
#define STACK_SIZE 4096
#define MAX_DIR_DEPTH 16
#define MAX_OPEN_FILES 64
#define MAX_FILENAME_LEN 64
#define MAX_PATH_LEN 512
#define MAX_ARGV 16
#define MAX_ENVP 32

// ELF Definitions
typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Word;

#define EI_NIDENT 16
#define EI_MAG0 0
#define ELFMAG0 0x7F
#define EI_MAG1 1
#define ELFMAG1 'E'
#define EI_MAG2 2
#define ELFMAG2 'L'
#define EI_MAG3 3
#define ELFMAG3 'F'
#define PT_LOAD 1
#define EI_CLASS 4
#define ELFCLASS32 1
#define EI_DATA 5
#define ELFDATA2LSB 1
#define ET_EXEC 2
#define EM_CUSTOM 0xFE01  // Наш кастомный тип CPU

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    Elf32_Word  p_type;
    Elf32_Off   p_offset;
    Elf32_Addr  p_vaddr;
    Elf32_Addr  p_paddr;
    Elf32_Word  p_filesz;
    Elf32_Word  p_memsz;
    Elf32_Word  p_flags;
    Elf32_Word  p_align;
} Elf32_Phdr;

// CPU registers
typedef struct {
    uint32_t pc;       // Program counter
    uint32_t sp;       // Stack pointer
    uint32_t regs[16]; // General purpose registers R0-R15
    uint32_t status;   // Status register
    uint32_t argc;     // Argument count
    uint32_t argv;     // Argument vector
    uint32_t envp;     // Environment variables
} CPUState;

// Task structure
typedef struct {
    CPUState cpu;
    uint32_t stack_start;
    uint32_t stack_size;
    uint8_t active;
    uint8_t priority;
    uint32_t pid;      // Process ID
    uint32_t ppid;     // Parent PID
} Task;

// Process table entry
typedef struct {
    uint32_t pid;
    uint32_t status;
    Task *task;
} Process;

// File metadata
typedef struct {
    char name[MAX_FILENAME_LEN + 1]; // Filename
    uint32_t start;    // Data start address or directory ID
    uint32_t size;     // File size
    uint8_t used;      // Usage flag
    uint8_t is_dir;    // Directory flag
    uint32_t parent;   // Parent directory ID
    uint8_t executable; // Executable flag
} FileMetadata;

// System call
typedef struct {
    uint32_t syscall_num;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;     // Additional argument
    uint32_t return_value;
} Syscall;

typedef struct {
    uint8_t *memory;   // Main memory
    size_t size;       // Memory size
    CPUState cpu;
    Task tasks[MAX_TASKS];
    Process processes[MAX_TASKS];
    uint8_t current_task;
    uint32_t next_pid;
    Syscall syscall;
    uint32_t dir_stack[MAX_DIR_DEPTH];
    uint8_t dir_stack_ptr;
    uint32_t total_file_bytes;  // File memory usage counter
} Microcontroller;

// Function prototypes
void init_cpu(CPUState *cpu, uint32_t stack_top);
int execute_instruction(Microcontroller *mc);
void handle_syscall(Microcontroller *mc);
void get_current_directory_path(Microcontroller *mc, char *buffer, size_t buf_size);
size_t calculate_min_metadata_memory();
int load_elf_binary(Microcontroller *mc, const char *filename, uint32_t *entry_point);
int execute_binary(Microcontroller *mc, const char *filename);
void setup_stack(Microcontroller *mc, uint32_t stack_top, int argc, char **argv, char **envp);

// Create microcontroller
Microcontroller *create_microcontroller(size_t mem_size) {
    Microcontroller *mc = malloc(sizeof(Microcontroller));
    if (!mc) return NULL;

    mc->memory = calloc(1, mem_size); // Zero initialization
    if (!mc->memory) {
        free(mc);
        return NULL;
    }

    mc->size = mem_size;
    mc->dir_stack_ptr = 0;
    mc->dir_stack[0] = 0; // Root directory
    mc->total_file_bytes = 0;
    mc->current_task = 0;
    mc->next_pid = 1;

    // Initialize tasks
    for (int i = 0; i < MAX_TASKS; i++) {
        mc->tasks[i].active = 0;
        mc->processes[i].pid = 0;
    }

    // Initialize CPU
    init_cpu(&mc->cpu, mem_size - 4);
    
    // Initialize filesystem
    uint32_t metadata_area_size = MAX_FILES * sizeof(FileMetadata);
    uint32_t data_start = DATA_START + metadata_area_size;
    *((uint32_t *)(mc->memory + METADATA_START)) = data_start;
    
    // Create root directory
    FileMetadata *root = (FileMetadata *)(mc->memory + DATA_START);
    strncpy(root->name, "/", MAX_FILENAME_LEN);
    root->start = 0;        // Root ID = 0
    root->size = 0;
    root->used = 1;
    root->is_dir = 1;
    root->parent = 0;       // Root has no parent
    root->executable = 0;

    return mc;
}

// Free microcontroller resources
void destroy_microcontroller(Microcontroller *mc) {
    if (mc) {
        free(mc->memory);
        free(mc);
    }
}

const char* bytes_to_human_readable(size_t bytes) {
    static char buffer[32];
    const char* suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    int suffix_index = 0;
    double count = bytes;

    while (count >= 1024 && suffix_index < 4) {
        count /= 1024;
        suffix_index++;
    }

    if (suffix_index == 0) {
        snprintf(buffer, sizeof(buffer), "%d %s", (int)count, suffixes[suffix_index]);
    } else if (count < 10) {
        snprintf(buffer, sizeof(buffer), "%.1f %s", count, suffixes[suffix_index]);
    } else {
        snprintf(buffer, sizeof(buffer), "%d %s", (int)(count + 0.5), suffixes[suffix_index]);
    }

    return buffer;
}

size_t calculate_min_metadata_memory() {
    // Calculate the size needed for metadata
    size_t total = 0;
    
    // Fixed metadata at start (data_start pointer)
    total += sizeof(uint32_t);  // METADATA_START
    
    // File metadata structures
    total += MAX_FILES * sizeof(FileMetadata);
    
    // CPU state structure
    total += sizeof(CPUState);
    
    // Task structures
    total += MAX_TASKS * sizeof(Task);
    
    // Process structures
    total += MAX_TASKS * sizeof(Process);
    
    // Directory stack
    total += MAX_DIR_DEPTH * sizeof(uint32_t);
    
    // System call structure
    total += sizeof(Syscall);
    
    // Other small variables
    total += sizeof(uint8_t) * 2 + sizeof(uint32_t) * 3;
    
    return total;
}

void microcontroller_memory_manager_realloc_show_menu(size_t memory_size) {
    printf("====================================\n");
    printf("|  Microcontroller Memory Realloc |\n");
    printf("====================================\n");
    printf("| Current memory size: %-10zu |\n", memory_size);
    printf("| set       - set new memory size  |\n");
    printf("| add       - add to exist memory  |\n");
    printf("| help      - show this menu       |\n");
    printf("| exit      - exit from realloc    |\n");
    printf("====================================\n");
}

void microcontroller_memory_manager_realloc_set(Microcontroller *mc) {
    uint32_t free_ptr = *((uint32_t *)(mc->memory + METADATA_START));
    uint32_t metadata_size = DATA_START + MAX_FILES * sizeof(FileMetadata);
    uint32_t stack_usage = 0;
    
    // Calculate stack usage
    for (int i = 0; i < MAX_TASKS; i++) {
        if (mc->tasks[i].active) {
            stack_usage += mc->tasks[i].stack_size;
        }
    }
    
    uint32_t active_used = metadata_size + mc->total_file_bytes + stack_usage;
    uint32_t free_space = mc->size - free_ptr;

    char input[1024];
    size_t min_size = active_used > DEFAULT_MEMORY_SIZE ? active_used : DEFAULT_MEMORY_SIZE;

    while (1) {
        printf("Minimum required memory: %zu bytes (%s)\n", min_size, bytes_to_human_readable(min_size));
        printf("Type 'exit' to cancel operation\n");
        printf("mcuOS/MCMM/realloc/set> ");
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "exit") == 0) {
            return;
        }
        
        size_t new_size = atol(input);
        if (new_size == 0) {
            printf("Invalid input. Please enter a valid number.\n");
            continue;
        }
        
        if (new_size < min_size) {
            printf("Error: New size must be at least %zu bytes\n", min_size);
            continue;
        }
        
        uint8_t *new_memory = realloc(mc->memory, new_size);
        if (!new_memory) {
            printf("Memory reallocation failed!\n");
            continue;
        }
        
        // Initialize new memory area to zero
        if (new_size > mc->size) {
            memset(new_memory + mc->size, 0, new_size - mc->size);
        }
        
        mc->memory = new_memory;
        mc->size = new_size;
        printf("Memory successfully resized to %zu bytes\n", new_size);
        return;
    }
}

void microcontroller_memory_manager_realloc_add(Microcontroller *mc) {
    char input[1024];
    size_t min_add = 1024; // Minimum 1KB

    while (1) {
        printf("Minimum addition: %zu bytes\n", min_add);
        printf("Type 'exit' to cancel operation\n");
        printf("mcuOS/MCMM/realloc/add> ");
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "exit") == 0) {
            return;
        }
        
        size_t add_size = atol(input);
        if (add_size < min_add) {
            printf("Error: Must add at least %zu bytes\n", min_add);
            continue;
        }
        
        size_t new_size = mc->size + add_size;
        uint8_t *new_memory = realloc(mc->memory, new_size);
        if (!new_memory) {
            printf("Memory reallocation failed!\n");
            continue;
        }
        
        // Initialize new memory area to zero
        memset(new_memory + mc->size, 0, add_size);
        
        mc->memory = new_memory;
        mc->size = new_size;
        printf("Successfully added %zu bytes. New size: %zu bytes\n", add_size, new_size);
        return;
    }
}

void microcontroller_memory_manager_realloc_menu(Microcontroller *mc, size_t memory_size) {
    char input[128];
    
    microcontroller_memory_manager_realloc_show_menu(memory_size);

    while (1) {
        printf("mcuOS/MCMM/realloc> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "exit") == 0) {
            return;
        }
        else if (strcmp(input, "set") == 0) {
            microcontroller_memory_manager_realloc_set(mc);
            microcontroller_memory_manager_realloc_show_menu(mc->size);
        }
        else if (strcmp(input, "add") == 0) {
            microcontroller_memory_manager_realloc_add(mc);
            microcontroller_memory_manager_realloc_show_menu(mc->size);
        }
        else if (strcmp(input, "help") == 0) {
            microcontroller_memory_manager_realloc_show_menu(mc->size);
        }
        else {
            printf("Unknown command. Type 'help' for options.\n");
        }
    }
}

void microcontroller_memory_manager_show_main_menu() {
    printf("====================================\n");
    printf("|  Microcontroller Memory Manager |\n");
    printf("====================================\n");
    printf("| info      - show memory info     |\n");
    printf("| realloc   - realloc memory       |\n");
    printf("| help      - show help menu       |\n");
    printf("| exit      - exit from manager    |\n");
    printf("====================================\n");
}

void microcontroller_memory_manager_info_menu(Microcontroller *mc) {
    uint32_t free_ptr = *((uint32_t *)(mc->memory + METADATA_START));
    uint32_t metadata_size = DATA_START + MAX_FILES * sizeof(FileMetadata);
    uint32_t stack_usage = 0;
    
    // Calculate stack usage
    for (int i = 0; i < MAX_TASKS; i++) {
        if (mc->tasks[i].active) {
            stack_usage += mc->tasks[i].stack_size;
        }
    }
    
    uint32_t active_used = metadata_size + mc->total_file_bytes + stack_usage;
    uint32_t free_space = mc->size - free_ptr;
    float usage_percent = (active_used * 100.0) / mc->size;
    
    printf("===============Memory information===============\n");
    printf("  Total memory:      %10zu bytes\n", mc->size);
    printf("  Metadata:          %10u bytes\n", metadata_size);
    printf("  File data:         %10u bytes\n", mc->total_file_bytes);
    printf("  Task stacks:       %10u bytes\n", stack_usage);
    printf("  Total used:        %10u bytes\n", active_used);
    printf("  Allocated:         %10u bytes\n", free_ptr);
    printf("  Free:              %10u bytes\n", free_space);
    printf("  Usage:             %10.1f%%\n", usage_percent);
    printf("================================================\n");
}

void microcontroller_memory_manager(Microcontroller *mc) {
    char input[256];
    microcontroller_memory_manager_show_main_menu();
    
    while (1) {
        printf("mcuOS/MCMM> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "help") == 0) {
            microcontroller_memory_manager_show_main_menu();
        }
        else if (strcmp(input, "exit") == 0) {
            return;
        }
        else if (strcmp(input, "info") == 0) {
            microcontroller_memory_manager_info_menu(mc);
        }
        else if (strcmp(input, "realloc") == 0) {
            microcontroller_memory_manager_realloc_menu(mc, mc->size);
            microcontroller_memory_manager_show_main_menu();
        }
        else {
            printf("Unknown command. Type 'help' for options.\n");
        }
    }
}

// Write byte to memory
void write_byte(Microcontroller *mc, uint32_t addr, uint8_t value) {
    if (addr < mc->size) mc->memory[addr] = value;
}

// Read byte from memory
uint8_t read_byte(Microcontroller *mc, uint32_t addr) {
    return (addr < mc->size) ? mc->memory[addr] : 0xFF;
}

// Get metadata slot
FileMetadata *get_metadata_slot(Microcontroller *mc, int index) {
    if (index < 0 || index >= MAX_FILES) return NULL;
    uint32_t offset = DATA_START + index * sizeof(FileMetadata);
    if (offset + sizeof(FileMetadata) > mc->size) return NULL;
    return (FileMetadata *)(mc->memory + offset);
}

// Get current directory path
void get_current_directory_path(Microcontroller *mc, char *buffer, size_t buf_size) {
    if (mc->dir_stack_ptr == 0) {
        strncpy(buffer, "/", buf_size);
        return;
    }

    buffer[0] = '\0';
    
    // For each directory in the stack (except root), prepend its name
    for (int i = 1; i <= mc->dir_stack_ptr; i++) {
        uint32_t dir_id = mc->dir_stack[i];
        
        // Find the directory metadata
        for (int j = 0; j < MAX_FILES; j++) {
            FileMetadata *meta = get_metadata_slot(mc, j);
            if (meta && meta->used && meta->is_dir && meta->start == dir_id) {
                strncat(buffer, "/", buf_size - strlen(buffer) - 1);
                strncat(buffer, meta->name, buf_size - strlen(buffer) - 1);
                break;
            }
        }
    }
    
    if (buffer[0] == '\0') {
        strncpy(buffer, "/", buf_size);
    }
}

// Show current directory
void show_current_directory(Microcontroller *mc) {
    char path[MAX_PATH_LEN + 1] = {0};
    get_current_directory_path(mc, path, sizeof(path));
    printf("Current directory: %s\n", path);
}

// Find file by name
FileMetadata *find_file(Microcontroller *mc, const char *filename) {
    if (!filename || !*filename) return NULL;
    
    uint32_t current_dir = mc->dir_stack[mc->dir_stack_ptr];
    
    for (int i = 0; i < MAX_FILES; i++) {
        FileMetadata *meta = get_metadata_slot(mc, i);
        if (meta && meta->used && meta->parent == current_dir && 
            strcmp(meta->name, filename) == 0) {
            return meta;
        }
    }
    return NULL;
}

// Create file or directory
int create_file(Microcontroller *mc, const char *filename, uint32_t size, uint8_t is_dir) {
    if (!filename || strlen(filename) > MAX_FILENAME_LEN) return -1;

    // Check if file exists
    if (find_file(mc, filename)) return -1;

    uint32_t free_ptr = *((uint32_t *)(mc->memory + METADATA_START));
    if (!is_dir && (free_ptr + size > mc->size)) return -1;

    uint32_t current_dir = mc->dir_stack[mc->dir_stack_ptr];
    
    for (int i = 0; i < MAX_FILES; i++) {
        FileMetadata *meta = get_metadata_slot(mc, i);
        if (meta && !meta->used) {
            strncpy(meta->name, filename, MAX_FILENAME_LEN);
            meta->name[MAX_FILENAME_LEN] = '\0';
            
            if (is_dir) {
                meta->start = i; 
                meta->size = 0;  
            } else {
                meta->start = free_ptr;
                meta->size = size; 
                mc->total_file_bytes += size;
            }
            
            meta->used = 1;
            meta->is_dir = is_dir;
            meta->parent = current_dir;
            meta->executable = 0;
            
            if (!is_dir) {
                *((uint32_t *)(mc->memory + METADATA_START)) = free_ptr + size;
            }
            return i; // Return file ID
        }
    }
    return -1;
}

// write_file_data function
int write_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *data, uint32_t len) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    uint32_t new_end = offset + len;
    if (new_end > meta->size) {
        mc->total_file_bytes += (new_end - meta->size);
        meta->size = new_end; 
    }
    
    for (uint32_t j = 0; j < len; j++) {
        write_byte(mc, meta->start + offset + j, data[j]);
    }
    return 0;
}

// Write instruction to file
void write_instruction(Microcontroller *mc, const char *filename, uint32_t offset, 
                      uint8_t opcode, uint8_t reg1, uint8_t reg2, uint8_t reg3, uint16_t imm) {
    uint8_t instruction[4];
    instruction[0] = opcode;
    instruction[1] = (reg1 << 4) | (reg2 & 0x0F);
    instruction[2] = (reg3 << 4) | ((imm >> 8) & 0x0F);
    instruction[3] = imm & 0xFF;
    
    write_file_data(mc, filename, offset, instruction, 4);
}

// Read data from file
int read_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *buffer, uint32_t len) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    if (offset > meta->size || offset + len > meta->size) return -1;
    
    for (uint32_t j = 0; j < len; j++) {
        buffer[j] = read_byte(mc, meta->start + offset + j);
    }
    return 0;
}

// Delete file
int delete_file(Microcontroller *mc, const char *filename) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta) return -1;
    
    // For directories, check if empty
    if (meta->is_dir) {
        for (int i = 0; i < MAX_FILES; i++) {
            FileMetadata *child = get_metadata_slot(mc, i);
            if (child && child->used && child->parent == meta->start) {
                return -1; // Directory not empty
            }
        }
    } else {
        // Update memory usage counter
        mc->total_file_bytes -= meta->size;
    }
    
    meta->used = 0;
    return 0;
}

// List files
void list_files(Microcontroller *mc) {
    uint32_t current_dir = mc->dir_stack[mc->dir_stack_ptr];
    
    printf("Current directory contents:\n");
    int count = 0;
    for (int i = 0; i < MAX_FILES; i++) {
        FileMetadata *meta = get_metadata_slot(mc, i);
        if (meta && meta->used && meta->parent == current_dir) {
            printf("  %s%-20s %-9s %u bytes %s\n", 
                   meta->is_dir ? "[D] " : "[F] ",
                   meta->name, 
                   meta->is_dir ? "DIR" : "FILE",
                   meta->size,
                   meta->executable ? "[X]" : "");
            count++;
        }
    }
    
    if (count == 0) {
        printf("  (empty)\n");
    }
}

// Change directory
int change_directory(Microcontroller *mc, const char *dirname) {
    if (strcmp(dirname, "..") == 0) {
        if (mc->dir_stack_ptr > 0) {
            mc->dir_stack_ptr--;
            return 0;
        }
        return -1;
    }
    
    if (strcmp(dirname, "/") == 0) {
        mc->dir_stack_ptr = 0;
        return 0;
    }
    
    FileMetadata *meta = find_file(mc, dirname);
    if (!meta || !meta->is_dir) return -1;
    
    if (mc->dir_stack_ptr < MAX_DIR_DEPTH - 1) {
        mc->dir_stack_ptr++;
        mc->dir_stack[mc->dir_stack_ptr] = meta->start;
        return 0;
    }
    return -1;
}

// Write bits to file
int write_bits_to_file(Microcontroller *mc, const char *filename, uint32_t bit_offset, uint8_t *bits, uint32_t bit_count) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;

    uint32_t byte_offset = bit_offset / 8;
    uint8_t bit_shift = bit_offset % 8;
    
    if (byte_offset >= meta->size) return -1;

    uint8_t current_byte = read_byte(mc, meta->start + byte_offset);
    
    for (uint32_t i = 0; i < bit_count; i++) {
        if (bits[i/8] & (1 << (i%8))) {
            current_byte |= (1 << bit_shift);
        } else {
            current_byte &= ~(1 << bit_shift);
        }
        
        bit_shift++;
        if (bit_shift >= 8) {
            write_byte(mc, meta->start + byte_offset, current_byte);
            byte_offset++;
            if (byte_offset >= meta->size) return -1;
            current_byte = read_byte(mc, meta->start + byte_offset);
            bit_shift = 0;
        }
    }

    if (bit_shift != 0) {
        write_byte(mc, meta->start + byte_offset, current_byte);
    }
    
    return 0;
}

// Create task
int create_task(Microcontroller *mc, const char *filename, uint8_t priority) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    // Find free task slot
    for (int i = 1; i < MAX_TASKS; i++) { // Slot 0 is main thread
        if (!mc->tasks[i].active) {
            uint32_t free_ptr = *((uint32_t *)(mc->memory + METADATA_START));
            if (free_ptr + STACK_SIZE > mc->size) {
                return -1;
            }
            
            // Initialize task
            Task *task = &mc->tasks[i];
            task->active = 1;
            task->priority = priority;
            task->pid = mc->next_pid++;
            task->ppid = mc->current_task == 0 ? 0 : mc->tasks[mc->current_task].pid;
            
            // Allocate stack
            task->stack_start = free_ptr;
            task->stack_size = STACK_SIZE;
            *((uint32_t *)(mc->memory + METADATA_START)) = free_ptr + STACK_SIZE;
            
            // Initialize CPU state
            init_cpu(&task->cpu, task->stack_start + STACK_SIZE - 4);
            task->cpu.pc = meta->start;
            
            // Initialize stack with zeros
            memset(mc->memory + free_ptr, 0, STACK_SIZE);
            
            // Add to process table
            mc->processes[i].pid = task->pid;
            mc->processes[i].status = 0; // Running
            mc->processes[i].task = task;
            
            return i;
        }
    }
    return -1;
}

// Task scheduler
void scheduler(Microcontroller *mc) {
    // Simple round-robin scheduler
    static uint8_t last_task = 0;
    
    for (int i = 1; i <= MAX_TASKS; i++) {
        uint8_t idx = (last_task + i) % MAX_TASKS;
        if (idx != 0 && mc->tasks[idx].active) {
            mc->current_task = idx;
            last_task = idx;
            return;
        }
    }
    
    // If no active tasks - use main thread
    mc->current_task = 0;
}

// Execute current task
void execute_current_task(Microcontroller *mc) {
    if (mc->current_task == 0) {
        // Main thread
        for (int i = 0; i < 100; i++) {
            if (!execute_instruction(mc)) break;
        }
    } else {
        // Tasks
        Task *task = &mc->tasks[mc->current_task];
        CPUState saved_cpu = mc->cpu;
        mc->cpu = task->cpu;
        
        for (int i = 0; i < 10; i++) {
            if (!execute_instruction(mc)) {
                task->active = 0;
                mc->processes[mc->current_task].status = 1; // Zombie
                break;
            }
        }
        
        task->cpu = mc->cpu;
        mc->cpu = saved_cpu;
    }
}

// Load external file
int load_external_file(Microcontroller *mc, const char *ext_path, const char *int_name) {
    // Check for NULL pointers
    if (!ext_path || !int_name) {
        printf("Error: NULL filename\n");
        return -1;
    }

    // Check filename lengths
    if (strlen(int_name) > MAX_FILENAME_LEN) {
        printf("Error: Internal name too long\n");
        return -1;
    }

    FILE *f = fopen(ext_path, "rb");
    if (!f) {
        perror("Error opening file");
        return -1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0) {
        printf("Error: Invalid file size\n");
        fclose(f);
        return -1;
    }
    
    uint8_t *buffer = malloc(size);
    if (!buffer) {
        printf("Error: Memory allocation failed\n");
        fclose(f);
        return -1;
    }
    
    size_t bytes_read = fread(buffer, 1, size, f);
    fclose(f);
    
    if (bytes_read != (size_t)size) {
        printf("Error: File read incomplete\n");
        free(buffer);
        return -1;
    }
    
    // Delete old file if exists
    FileMetadata *old = find_file(mc, int_name);
    if (old) {
        if (delete_file(mc, int_name) < 0) {
            printf("Error: Couldn't delete existing file\n");
            free(buffer);
            return -1;
        }
    }
    
    if (create_file(mc, int_name, size, 0) < 0) {
        printf("Error: Couldn't create new file\n");
        free(buffer);
        return -1;
    }
    
    int result = write_file_data(mc, int_name, 0, buffer, size);
    free(buffer);
    
    if (result < 0) {
        printf("Error: Writing file data failed\n");
        return -1;
    }
    
    // Mark as executable if it's a binary
    if (strstr(ext_path, ".bin") || strstr(ext_path, ".elf")) {
        FileMetadata *meta = find_file(mc, int_name);
        if (meta) {
            meta->executable = 1;
        }
    }
    
    return 0;
}

// Setup stack for new process
void setup_stack(Microcontroller *mc, uint32_t stack_top, int argc, char **argv, char **envp) {
    uint32_t sp = stack_top;
    
    // Write argument count
    sp -= 4;
    *((uint32_t*)(mc->memory + sp)) = argc;
    
    // Write argument pointers
    uint32_t argv_addr = sp - 4 * (argc + 1);
    sp = argv_addr;
    for (int i = 0; i < argc; i++) {
        int len = strlen(argv[i]) + 1;
        sp -= len;
        memcpy(mc->memory + sp, argv[i], len);
        *((uint32_t*)(mc->memory + argv_addr + i*4)) = sp;
    }
    *((uint32_t*)(mc->memory + argv_addr + argc*4)) = 0; // NULL terminator
    
    // Write environment pointers
    uint32_t envp_addr = argv_addr - 4 * (MAX_ENVP + 1);
    sp = envp_addr;
    int env_count = 0;
    for (int i = 0; envp[i] && i < MAX_ENVP; i++) {
        int len = strlen(envp[i]) + 1;
        sp -= len;
        memcpy(mc->memory + sp, envp[i], len);
        *((uint32_t*)(mc->memory + envp_addr + i*4)) = sp;
        env_count++;
    }
    *((uint32_t*)(mc->memory + envp_addr + env_count*4)) = 0; // NULL terminator
    
    // Update CPU registers
    mc->cpu.argc = argc;
    mc->cpu.argv = argv_addr;
    mc->cpu.envp = envp_addr;
    mc->cpu.sp = sp;
}

// Load ELF binary
int load_elf_binary(Microcontroller *mc, const char *filename, uint32_t *entry_point) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) {
        printf("File not found or is directory\n");
        return -1;
    }

    Elf32_Ehdr ehdr;
    if (read_file_data(mc, filename, 0, (uint8_t*)&ehdr, sizeof(ehdr))) {
        printf("Failed to read ELF header\n");
        return -1;
    }

    // Verify ELF magic
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        printf("Invalid ELF magic\n");
        return -1;
    }
    
    // Check ELF class (32-bit)
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Not a 32-bit ELF file\n");
        return -1;
    }
    
    // Check data encoding (little-endian)
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        printf("Not a little-endian ELF file\n");
        return -1;
    }
    
    // Check type (executable)
    if (ehdr.e_type != ET_EXEC) {
        printf("Not an executable ELF file\n");
        return -1;
    }
    
    // Check machine type (our custom CPU)
    if (ehdr.e_machine != EM_CUSTOM) {
        printf("Unsupported machine type: 0x%04X\n", ehdr.e_machine);
        return -1;
    }

    // Read program headers
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf32_Phdr phdr;
        uint32_t phdr_offset = ehdr.e_phoff + i * ehdr.e_phentsize;
        if (read_file_data(mc, filename, phdr_offset, (uint8_t*)&phdr, sizeof(phdr))) {
            printf("Failed to read program header %d\n", i);
            return -1;
        }

        if (phdr.p_type == PT_LOAD) {
            // Check memory bounds
            if (phdr.p_vaddr + phdr.p_memsz > mc->size) {
                printf("Segment %d out of memory bounds\n", i);
                return -1;
            }

            // Read segment data
            for (uint32_t off = 0; off < phdr.p_filesz; off++) {
                uint8_t byte;
                if (read_file_data(mc, filename, phdr.p_offset + off, &byte, 1)) {
                    printf("Failed to read segment data %d at offset %u\n", i, off);
                    return -1;
                }
                write_byte(mc, phdr.p_vaddr + off, byte);
            }

            // Zero out remaining part of the segment in memory
            for (uint32_t off = phdr.p_filesz; off < phdr.p_memsz; off++) {
                write_byte(mc, phdr.p_vaddr + off, 0);
            }
        }
    }

    *entry_point = ehdr.e_entry;
    return 0;
}

// Execute binary program
int execute_binary(Microcontroller *mc, const char *filename) {
    uint32_t entry_point;
    
    // Load ELF binary
    if (load_elf_binary(mc, filename, &entry_point) != 0) {
        printf("Failed to load ELF binary: %s\n", filename);
        return -1;
    }
    
    // Set up stack
    char *argv[] = { (char*)filename, NULL };
    char *envp[] = { "PATH=/bin", "HOME=/", NULL };
    setup_stack(mc, mc->size - 4, 1, argv, envp);
    
    // Save current CPU state
    CPUState saved_cpu = mc->cpu;
    
    // Set program counter to entry point
    mc->cpu.pc = entry_point;
    
    // Execute until HALT
    while (execute_instruction(mc)) {}
    
    // Restore CPU state
    mc->cpu = saved_cpu;
    
    return 0;
}

// ================================
// CPU Implementation
// ================================

// Initialize CPU
void init_cpu(CPUState *cpu, uint32_t stack_top) {
    memset(cpu, 0, sizeof(CPUState));
    cpu->sp = stack_top;  // Set to top of stack
}

// Handle system calls
void handle_syscall(Microcontroller *mc) {
    Syscall *sc = &mc->syscall;
    sc->return_value = 0;
    
    switch(sc->syscall_num) {
        case 0: // Exit
            if (mc->current_task != 0) {
                mc->tasks[mc->current_task].active = 0;
                mc->processes[mc->current_task].status = 1; // Zombie
            }
            break;
            
        case 1: // Fork
            // Simple fork implementation - just return 0 for child, PID for parent
            if (mc->current_task == 0) {
                sc->return_value = -1; // Can't fork main thread
            } else {
                int new_task = create_task(mc, "forked", mc->tasks[mc->current_task].priority);
                if (new_task > 0) {
                    // Copy CPU state to child
                    mc->tasks[new_task].cpu = mc->tasks[mc->current_task].cpu;
                    sc->return_value = mc->tasks[new_task].pid; // Return child PID to parent
                    mc->tasks[new_task].cpu.regs[0] = 0; // Return 0 to child
                } else {
                    sc->return_value = -1;
                }
            }
            break;
            
        case 2: // Read file
        {
            char filename[MAX_PATH_LEN + 1];
            uint32_t addr = sc->arg1;
            int i = 0;
            for (; i < MAX_PATH_LEN; i++) {
                uint8_t c = read_byte(mc, addr++);
                if (!c) break;
                filename[i] = c;
            }
            filename[i] = 0;
            
            uint32_t offset = sc->arg2;
            uint8_t *buffer = mc->memory + sc->arg3;
            uint32_t len = sc->arg4;
            
            if (read_file_data(mc, filename, offset, buffer, len) == 0) {
                sc->return_value = len;
            } else {
                sc->return_value = -1;
            }
            break;
        }
            
        case 3: // Write to file
        {
            char filename[MAX_PATH_LEN + 1];
            uint32_t addr = sc->arg1;
            int i = 0;
            for (; i < MAX_PATH_LEN; i++) {
                uint8_t c = read_byte(mc, addr++);
                if (!c) break;
                filename[i] = c;
            }
            filename[i] = 0;
            
            uint32_t offset = sc->arg2;
            uint8_t *data = mc->memory + sc->arg3;
            uint32_t len = sc->arg4;
            
            if (write_file_data(mc, filename, offset, data, len) == 0) {
                sc->return_value = len;
            } else {
                sc->return_value = -1;
            }
            break;
        }
            
        case 4: // Create file
        {
            char filename[MAX_PATH_LEN + 1];
            uint32_t addr = sc->arg1;
            int i = 0;
            for (; i < MAX_PATH_LEN; i++) {
                uint8_t c = read_byte(mc, addr++);
                if (!c) break;
                filename[i] = c;
            }
            filename[i] = 0;
            
            uint32_t size = sc->arg2;
            
            if (create_file(mc, filename, size, 0) >= 0) {
                sc->return_value = 0;
            } else {
                sc->return_value = -1;
            }
            break;
        }
        case 5: // Write bits to file
        {
            char filename[MAX_PATH_LEN + 1];
            uint32_t addr = sc->arg1;
            int i = 0;
            for (; i < MAX_PATH_LEN; i++) {
                uint8_t c = read_byte(mc, addr++);
                if (!c) break;
                filename[i] = c;
            }
            filename[i] = 0;
            
            uint32_t bit_offset = sc->arg2;
            uint8_t *bits = mc->memory + sc->arg3;
            uint32_t bit_count = sc->arg4;
            
            if (write_bits_to_file(mc, filename, bit_offset, bits, bit_count) == 0) {
                sc->return_value = bit_count;
            } else {
                sc->return_value = -1;
            }
            break;
        }
            
        case 6: // Execute binary
        {
            char filename[MAX_PATH_LEN + 1];
            uint32_t addr = sc->arg1;
            int i = 0;
            for (; i < MAX_PATH_LEN; i++) {
                uint8_t c = read_byte(mc, addr++);
                if (!c) break;
                filename[i] = c;
            }
            filename[i] = 0;
            
            sc->return_value = execute_binary(mc, filename);
            break;
        }
            
        case 7: // Execve
        {
            char filename[MAX_PATH_LEN + 1];
            uint32_t addr = sc->arg1;
            int i = 0;
            for (; i < MAX_PATH_LEN; i++) {
                uint8_t c = read_byte(mc, addr++);
                if (!c) break;
                filename[i] = c;
            }
            filename[i] = 0;
            
            // For simplicity, we'll just execute the binary
            sc->return_value = execute_binary(mc, filename);
            break;
        }
            
        case 8: // Waitpid
            // Simple wait implementation - just return immediately
            sc->return_value = 0;
            break;
            
        case 0x10: // Print character
            putchar(sc->arg1 & 0xFF);
            fflush(stdout);
            break;
            
        case 0x11: // Read character
            sc->return_value = getchar();
            break;
            
        default:
            printf("Unknown syscall: %d\n", sc->syscall_num);
    }
    
    mc->cpu.regs[0] = sc->return_value;
}

// Execute instruction
int execute_instruction(Microcontroller *mc) {
    // Check instruction address
    if (mc->cpu.pc >= mc->size - 3) return 0;
    
    uint32_t instr = 0;
    for (int i = 0; i < 4; i++) {
        instr = (instr << 8) | read_byte(mc, mc->cpu.pc++);
    }
    
    uint8_t opcode = (instr >> 24) & 0xFF;
    uint8_t reg1 = (instr >> 20) & 0x0F;
    uint8_t reg2 = (instr >> 16) & 0x0F;
    uint8_t reg3 = (instr >> 12) & 0x0F;
    uint16_t imm = instr & 0xFFFF;
    int32_t simm = (int32_t)(int16_t)imm; // Sign extension
    
    switch(opcode) {
        case 0x00: // NOP
            break;
            
        case 0x01: // MOV Rdest, #imm
            mc->cpu.regs[reg1] = imm;
            break;
            
        case 0x02: // ADD Rd, Rs1, Rs2
            mc->cpu.regs[reg1] = mc->cpu.regs[reg2] + mc->cpu.regs[reg3];
            break;
            
        case 0x03: // SUB Rd, Rs1, Rs2
            mc->cpu.regs[reg1] = mc->cpu.regs[reg2] - mc->cpu.regs[reg3];
            break;
            
        case 0x04: // LOAD Rd, [Rs + off]
            {
                uint32_t addr = mc->cpu.regs[reg2] + imm;
                if (addr > mc->size - 4) break;
                mc->cpu.regs[reg1] = 0;
                for (int i = 0; i < 4; i++) {
                    mc->cpu.regs[reg1] |= read_byte(mc, addr + i) << (i * 8);
                }
            }
            break;
            
        case 0x05: // STORE Rd, [Rs + off]
            {
                uint32_t addr = mc->cpu.regs[reg2] + imm;
                if (addr > mc->size - 4) break;
                uint32_t value = mc->cpu.regs[reg1];
                for (int i = 0; i < 4; i++) {
                    write_byte(mc, addr + i, (value >> (i * 8)) & 0xFF);
                }
            }
            break;
            
        case 0x06: // JMP #imm
            mc->cpu.pc += simm;
            break;
            
        case 0x07: // JZ Rs, #imm
            if (mc->cpu.regs[reg1] == 0) {
                mc->cpu.pc += simm;
            }
            break;
            
        case 0x08: // PUSH Rs
            {
                uint32_t value = mc->cpu.regs[reg1];
                if (mc->cpu.sp < 4) break;
                mc->cpu.sp -= 4;
                for (int i = 0; i < 4; i++) {
                    write_byte(mc, mc->cpu.sp + i, (value >> (i * 8)) & 0xFF);
                }
                break;
            }
            
        case 0x09: // POP Rd
            {
                if (mc->cpu.sp > mc->size - 4) break;
                uint32_t value = 0;
                for (int i = 0; i < 4; i++) {
                    value |= read_byte(mc, mc->cpu.sp + i) << (i * 8);
                }
                mc->cpu.sp += 4;
                mc->cpu.regs[reg1] = value;
                break;
            }

        case 0x20: // Delay
            usleep(mc->cpu.regs[0] * 1000);
            break;
            
        case 0x0A: // System call
            mc->syscall.syscall_num = mc->cpu.regs[0];
            mc->syscall.arg1 = mc->cpu.regs[1];
            mc->syscall.arg2 = mc->cpu.regs[2];
            mc->syscall.arg3 = mc->cpu.regs[3];
            mc->syscall.arg4 = mc->cpu.regs[4];
            handle_syscall(mc);
            break;
            
        case 0xFF: // Halt
            return 0;
            
        case 0x0B: // Write bits
            mc->syscall.syscall_num = 5; 
            mc->syscall.arg1 = mc->cpu.regs[1];
            mc->syscall.arg2 = mc->cpu.regs[2];
            mc->syscall.arg3 = mc->cpu.regs[3];
            mc->syscall.arg4 = mc->cpu.regs[4];
            handle_syscall(mc);
            break;
            
        case 0x0C: // Execute binary instruction
            mc->syscall.syscall_num = 6;
            mc->syscall.arg1 = mc->cpu.regs[1];
            handle_syscall(mc);
            break;
            
        default:
            printf("ERROR: Unknown instruction: 0x%02X\n", opcode);
            return 0;
    }
    
    return 1;
}

// ================================
// Command Interface
// ================================

// Show command interface
void show_interface() {
    printf("\n");
    printf("===========================================\n");
    printf("|    Microcontroller Operating System     |\n");
    printf("|=========================================|\n");
    printf("| Commands:                               |\n");
    printf("|   ls        - List files                |\n");
    printf("|   mkdir     - Create directory          |\n");
    printf("|   cd        - Change directory          |\n");
    printf("|   pwd       - Show current dir          |\n");
    printf("|   create    - Create file               |\n");
    printf("|   write     - Write to file             |\n");
    printf("|   read      - Read file                 |\n");
    printf("|   rm        - Delete file               |\n");
    printf("|   run       - Execute program           |\n");
    printf("|   runbin    - Execute binary file       |\n");
    printf("|   task      - Create task               |\n");
    printf("|   load      - Load external file        |\n");
    printf("|   mem       - Memory information        |\n");
    printf("|   man       - Command manual            |\n");
    printf("|   clear     - clear screen              |\n");
    printf("|   exit      - Exit                      |\n");
    printf("|   makeprog  - Create test program       |\n");
    printf("|   writeinst - Write instruction         |\n");
    printf("|   chmod     - Set executable flag       |\n");
    printf("===========================================\n");
}

// Create test program
void create_sample_program(Microcontroller *mc) {
    if (create_file(mc, "test.bin", 256, 0) < 0) {
        printf("Error creating program file\n");
        return;
    }

    // MOV R0, #42
    write_instruction(mc, "test.bin", 0, 0x01, 0, 0, 0, 0x2A);
    // MOV R1, #15
    write_instruction(mc, "test.bin", 4, 0x01, 1, 0, 0, 0x0F);
    // ADD R2, R0, R1
    write_instruction(mc, "test.bin", 8, 0x02, 2, 0, 1, 0x00);
    // SYSCALL (print R0)
    write_instruction(mc, "test.bin", 12, 0x0A, 0, 0, 0, 0x10);
    // HALT
    write_instruction(mc, "test.bin", 16, 0xFF, 0, 0, 0, 0x00);
    
    // Mark as executable
    FileMetadata *meta = find_file(mc, "test.bin");
    if (meta) {
        meta->executable = 1;
    }
    
    printf("Test program written to test.bin (20 bytes)\n");
    printf("Execute: run test.bin\n");
}

// Show command manual
void show_manual(const char *cmd) {
    if (strcmp(cmd, "ls") == 0) {
        printf("ls: Show files in current directory\n");
        printf("Usage: ls\n");
    } 
    else if (strcmp(cmd, "pwd") == 0) {
        printf("pwd: show current directory\n");
        printf("Usage: pwd\n");
    }
    else if (strcmp(cmd, "mkdir") == 0) {
        printf("mkdir: Create new directory\n");
        printf("Usage: mkdir <directory_name>\n");
    }
    else if (strcmp(cmd, "cd") == 0) {
        printf("cd: Change current directory\n");
        printf("Usage: cd <directory_name>\n");
        printf("       cd ..  (go to parent directory)\n");
        printf("       cd /   (go to root directory)\n");
    }
    else if (strcmp(cmd, "create") == 0) {
        printf("create: Create new file\n");
        printf("Usage: create <filename> <size_in_bytes>\n");
    }
    else if (strcmp(cmd, "write") == 0) {
        printf("write: Write data to file\n");
        printf("Usage: write <file> <offset> <data>\n");
        printf("Example: write hello.txt 0 \"Hello world\"\n");
    }
    else if (strcmp(cmd, "read") == 0) {
        printf("read: Read data from file\n");
        printf("Usage: read <file> <offset> <length>\n");
        printf("Example: read hello.txt 0 11\n");
    }
    else if (strcmp(cmd, "rm") == 0) {
        printf("rm: Delete file or directory\n");
        printf("Usage: rm <filename>\n");
        printf("Note: Directory must be empty\n");
    }
    else if (strcmp(cmd, "run") == 0) {
        printf("run: Execute program\n");
        printf("Usage: run <program_file>\n");
    }
    else if (strcmp(cmd, "runbin") == 0) {
        printf("runbin: Execute ELF binary file\n");
        printf("Usage: runbin <binary_file>\n");
    }
    else if (strcmp(cmd, "task") == 0) {
        printf("task: Create new task\n");
        printf("Usage: task <file> <priority>\n");
        printf("Priority: 0 (lowest) to 255 (highest)\n");
    }
    else if (strcmp(cmd, "load") == 0) {
        printf("load: Load external file into system\n");
        printf("Usage: load <external_path> <internal_name>\n");
        printf("Example: load /home/user/program.bin app\n");
    }
    else if (strcmp(cmd, "mem") == 0) {
        printf("mem: Show memory usage\n");
        printf("Usage: mem\n");
    }
    else if (strcmp(cmd, "man") == 0) {
        printf("man: Command manual\n");
        printf("Usage: man <command_name>\n");
        printf("Example: man create\n");
    }
    else if (strcmp(cmd, "clear") == 0) {
        printf("clear: clear screen\n");
        printf("Usage: clear\n");
    }
    else if (strcmp(cmd, "exit") == 0) {
        printf("exit: Exit system\n");
        printf("Usage: exit\n");
    }
    else if (strcmp(cmd, "makeprog") == 0) {
        printf("makeprog: Create test program\n");
        printf("Usage: makeprog\n");
    }
    else if (strcmp(cmd, "writeinst") == 0) {
        printf("writeinst: Write instruction to file\n");
        printf("Usage: writeinst <file> <offset> <opcode_hex> <reg1> <reg2> <reg3> <imm>\n");
        printf("Example: writeinst program.bin 0 01 0 0 0 42   # MOV R0, #42\n");
    }
    else if (strcmp(cmd, "chmod") == 0) {
        printf("chmod: Set executable flag\n");
        printf("Usage: chmod +x <filename>\n");
    }
    else {
        printf("No manual for: %s\n", cmd);
        printf("Available commands: ls, mkdir, cd, create, write, read, rm, run, runbin, task, load, mem, man, exit, makeprog, writeinst, chmod\n");
    }
}

// Process command
void process_command(Microcontroller *mc, const char *cmd_line) {
    char cmd[256];
    strncpy(cmd, cmd_line, sizeof(cmd));
    cmd[sizeof(cmd)-1] = '\0';

    // Split command into tokens
    char *tokens[10] = {0};
    int argc = 0;
    
    char *token = strtok(cmd, " ");
    while (token != NULL && argc < 10) {
        tokens[argc++] = token;
        token = strtok(NULL, " ");
    }
    
    if (argc == 0) return;
    
    const char *command = tokens[0];
    const char *arg1 = argc > 1 ? tokens[1] : "";
    const char *arg2 = argc > 2 ? tokens[2] : "";
    const char *arg3 = argc > 3 ? tokens[3] : "";
    const char *arg4 = argc > 4 ? tokens[4] : "";
    const char *arg5 = argc > 5 ? tokens[5] : "";
    const char *arg6 = argc > 6 ? tokens[6] : "";
    const char *arg7 = argc > 7 ? tokens[7] : "";
    
    if (strcmp(command, "ls") == 0 || strcmp(command, "dir") == 0) {
        list_files(mc);
    }
    else if (strcmp(command, "mkdir") == 0 && argc >= 2) {
        if (create_file(mc, arg1, 0, 1) >= 0) {
            printf("Directory '%s' created\n", arg1);
        } else {
            printf("Error creating directory\n");
        }
    }
    else if (strcmp(command, "pwd") == 0) {
        show_current_directory(mc);
    }
    else if (strcmp(command, "cd") == 0 && argc >= 2) {
        if (change_directory(mc, arg1) == 0) {
            printf("Directory changed\n");
        } else {
            printf("Directory not found\n");
        }
    }
    else if (strcmp(command, "create") == 0 && argc >= 3) {
        uint32_t size = atoi(arg2);
        if (create_file(mc, arg1, size, 0) >= 0) {
            printf("File '%s' created (%u bytes)\n", arg1, size);
        } else {
            printf("Error creating file\n");
        }
    }
    else if (strcmp(command, "write") == 0 && argc >= 4) {
        uint32_t offset = atoi(arg2);
        uint32_t len = strlen(arg3);
        uint8_t data[256];
        
        if (len > sizeof(data)) len = sizeof(data);
        memcpy(data, arg3, len);
        
        if (write_file_data(mc, arg1, offset, data, len) == 0) {
            printf("Written %d bytes to '%s'\n", len, arg1);
        } else {
            printf("Write error\n");
        }
    }
    else if (strcmp(command, "read") == 0 && argc >= 4) {
        uint32_t offset = atoi(arg2);
        uint32_t len = atoi(arg3);
        uint8_t data[256];
        
        if (len > sizeof(data)) len = sizeof(data);
        
        if (read_file_data(mc, arg1, offset, data, len) == 0) {
            printf("Data from '%s':\n", arg1);
            for (uint32_t i = 0; i < len; i++) {
                if (isprint(data[i])) putchar(data[i]);
                else printf("\\x%02X", data[i]);
            }
            printf("\n");
        } else {
            printf("Read error\n");
        }
    }
    else if (strcmp(command, "rm") == 0 && argc >= 2) {
        if (delete_file(mc, arg1) == 0) {
            printf("File '%s' deleted\n", arg1);
        } else {
            printf("Delete error\n");
        }
    }
    else if (strcmp(command, "run") == 0 && argc >= 2) {
        FileMetadata *meta = find_file(mc, arg1);
        if (meta && !meta->is_dir) {
            CPUState saved_cpu = mc->cpu;
            mc->cpu.pc = meta->start;
            
            while (execute_instruction(mc)) {
                // Execute until HALT
            }
            
            mc->cpu = saved_cpu;
            printf("Program finished\n");
        } else {
            printf("Program not found\n");
        }
    }
    else if (strcmp(command, "runbin") == 0 && argc >= 2) {
        if (execute_binary(mc, arg1) == 0) {
            printf("Binary execution finished\n");
        } else {
            printf("Error executing binary\n");
        }
    }
    else if (strcmp(command, "task") == 0 && argc >= 3) {
        uint8_t priority = atoi(arg2);
        int task_id = create_task(mc, arg1, priority);
        if (task_id >= 0) {
            printf("Task created (ID: %d)\n", task_id);
        } else {
            printf("Error creating task\n");
        }
    }
    
    else if (strcmp(command, "load") == 0) {
        if (argc < 3) {
            printf("Usage: load <external_path> <internal_name>\n");
            return;
        }
        
        if (load_external_file(mc, arg1, arg2) == 0) {
            printf("File '%s' loaded as '%s'\n", arg1, arg2);
        } else {
            printf("Failed to load file\n");
        }
    }
    else if (strcmp(command, "mem") == 0) {
        microcontroller_memory_manager(mc);
    }
    else if (strcmp(command, "clear") == 0) {
        printf("\033[2J\033[H");
    }
    else if (strcmp(command, "makeprog") == 0) {
        create_sample_program(mc);
    }
    else if (strcmp(command, "writeinst") == 0 && argc >= 8) {
        uint32_t offset = atoi(arg2);
        uint8_t opcode = (uint8_t)strtoul(arg3, NULL, 16);  // HEX format
        uint8_t reg1 = (uint8_t)atoi(arg4);
        uint8_t reg2 = (uint8_t)atoi(arg5);
        uint8_t reg3 = (uint8_t)atoi(arg6);
        uint16_t imm = (uint16_t)atoi(arg7);
        
        write_instruction(mc, arg1, offset, opcode, reg1, reg2, reg3, imm);
        printf("Instruction written to %s at offset %u\n", arg1, offset);
    }
    else if (strcmp(command, "chmod") == 0 && argc >= 3) {
        if (strcmp(arg1, "+x") == 0) {
            FileMetadata *meta = find_file(mc, arg2);
            if (meta) {
                meta->executable = 1;
                printf("File '%s' marked as executable\n", arg2);
            } else {
                printf("File not found\n");
            }
        } else {
            printf("Usage: chmod +x <filename>\n");
        }
    }
    else if (strcmp(command, "man") == 0 && argc >= 2) {
        show_manual(arg1);
    }
    else if (strcmp(command, "exit") == 0) {
        printf("Exiting...\n");
        exit(0);
    }
    else if (strcmp(command, "help") == 0) {
        show_interface();
    }
    else {
        printf("Unknown command: %s\n", command);
        printf("Type 'help' for command list\n");
    }
}

int main() {
    printf("\033[2J\033[H"); // Clear screen

    size_t min_need_memory = calculate_min_metadata_memory();
    size_t memory_size = 0;
    char input[1024];

    printf("================================================================\n");
    printf("| Microcontroller OS - Memory Configuration                    |\n");
    printf("================================================================\n");
    printf("| Minimum required memory: %-8zu bytes (%s)          |\n", 
           min_need_memory, bytes_to_human_readable(min_need_memory));
    printf("| Default memory size:    %-8d bytes (%s)          |\n", 
           DEFAULT_MEMORY_SIZE, bytes_to_human_readable(DEFAULT_MEMORY_SIZE));
    printf("|                                                              |\n");
    printf("| Enter memory size in bytes or press Enter for default:        |\n");
    printf("================================================================\n");
    
    printf("memory_size> ");
    if (!fgets(input, sizeof(input), stdin)) return 1;
    input[strcspn(input, "\n")] = '\0';
    
    if (strlen(input) == 0) {
        memory_size = DEFAULT_MEMORY_SIZE;
    } else {
        memory_size = atol(input);
        if (memory_size < min_need_memory) {
            printf("Error: Memory size must be at least %zu bytes\n", min_need_memory);
            return 1;
        }
    }

    Microcontroller *mcu = create_microcontroller(memory_size);
    if (!mcu) {
        printf("Failed to initialize microcontroller!\n");
        return 1;
    }
    
    printf("\nMicrocontroller OS initialized with %zu bytes of memory\n", memory_size);
    printf("Type 'help' for command list\n\n");
    
    while (1) {
        printf("mcuOS> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strlen(input) > 0) {
            if (strcmp(input, "run_tasks") == 0) {
                scheduler(mcu);
                execute_current_task(mcu);
            } else {
                process_command(mcu, input);
            }
        }
    }

    destroy_microcontroller(mcu);
    return 0;
}