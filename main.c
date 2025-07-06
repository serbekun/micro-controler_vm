#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <elf.h>

#define METADATA_START 0
#define DEFAULT_MEMORY_SIZE (4 * 1024 * 1024)  // 4MB
#define DATA_START (sizeof(uint32_t))
#define MAX_FILES 32
#define MAX_DIR_DEPTH 8
#define MAX_FILENAME_LEN 32
#define MAX_PATH_LEN 512

// File metadata
typedef struct {
    char name[MAX_FILENAME_LEN + 1]; // Filename
    uint32_t start;    // Data start address or directory ID
    uint32_t size;     // File size
    uint8_t used;      // Usage flag
    uint8_t is_dir;    // Directory flag
    uint32_t parent;   // Parent directory ID
} FileMetadata;

typedef struct {
    uint32_t entry_point;   
    uint32_t phdr_offset;   
    uint16_t phnum;         
    uint8_t is_loaded;      
} ExecContext;

typedef struct {
    uint8_t *memory;        // point to all vm memory
    size_t size;            
    uint32_t dir_stack[MAX_DIR_DEPTH];
    uint8_t dir_stack_ptr;
    uint32_t total_file_bytes; 
    ExecContext exec_ctx;   
} Microcontroller;

// Function prototypes
void get_current_directory_path(Microcontroller *mc, char *buffer, size_t buf_size);
size_t calculate_min_metadata_memory();
int load_elf(Microcontroller *mc, const char *filename);
int execute_program(Microcontroller *mc);
void handle_syscall(Microcontroller *mc, uint32_t syscall_num, uint32_t arg1, uint32_t arg2, uint32_t arg3);
FileMetadata *find_file(Microcontroller *mc, const char *filename);
int create_file(Microcontroller *mc, const char *filename, uint32_t size, uint8_t is_dir);
int read_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *buffer, uint32_t len);
int write_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *data, uint32_t len);

// Create microcontroller
Microcontroller *create_microcontroller(size_t mem_size) {
    Microcontroller *mc = malloc(sizeof(Microcontroller));
    if (!mc) return NULL;

    mc->memory = calloc(1, mem_size);
    if (!mc->memory) {
        free(mc);
        return NULL;
    }

    mc->size = mem_size;
    mc->dir_stack_ptr = 0;
    mc->dir_stack[0] = 0;
    mc->total_file_bytes = 0;

    mc->exec_ctx.entry_point = 0;
    mc->exec_ctx.phdr_offset = 0;
    mc->exec_ctx.phnum = 0;
    mc->exec_ctx.is_loaded = 0;

    uint32_t metadata_area_size = MAX_FILES * sizeof(FileMetadata);
    uint32_t data_start = DATA_START + metadata_area_size;

    *((uint32_t *)(mc->memory + METADATA_START)) = data_start;

    FileMetadata *root = (FileMetadata *)(mc->memory + DATA_START);
    strncpy(root->name, "/", MAX_FILENAME_LEN);
    root->start = 0;
    root->size = 0;
    root->used = 1;
    root->is_dir = 1;
    root->parent = 0;

    create_file(mc, "stdin", 0, 0);
    create_file(mc, "stdout", 0, 0);
    create_file(mc, "stderr", 0, 0);
    create_file(mc, "syscall_output.txt", 0, 0);
    create_file(mc, "syscall_input.txt", 0, 0);

    return mc;
}

// Free microcontroller resources
void destroy_microcontroller(Microcontroller *mc) {
    if (mc) {
        free(mc->memory);
        free(mc);
    }
}

int load_elf(Microcontroller *mc, const char *filename) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) {
        printf("File not found or is directory\n");
        return -1;
    }

    Elf32_Ehdr ehdr;
    if (read_file_data(mc, filename, 0, (uint8_t*)&ehdr, sizeof(ehdr)) < 0) {
        printf("Failed to read ELF header\n");
        return -1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Invalid ELF signature\n");
        return -1;
    }

    if (ehdr.e_machine != EM_386) {
        printf("Unsupported architecture: %d\n", ehdr.e_machine);
        return -1;
    }

    mc->exec_ctx.entry_point = ehdr.e_entry;
    mc->exec_ctx.phdr_offset = ehdr.e_phoff;
    mc->exec_ctx.phnum = ehdr.e_phnum;
    mc->exec_ctx.is_loaded = 1;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf32_Phdr phdr;
        uint32_t offset = ehdr.e_phoff + i * sizeof(Elf32_Phdr);

        if (read_file_data(mc, filename, offset, (uint8_t*)&phdr, sizeof(phdr)) < 0) {
            printf("Failed to read program header %d\n", i);
            return -1;
        }

        if (phdr.p_type == PT_LOAD) {
            if (phdr.p_vaddr + phdr.p_memsz > mc->size) {
                printf("Not enough memory for segment %d\n", i);
                return -1;
            }

            uint8_t *seg_data = malloc(phdr.p_filesz);
            if (!seg_data) {
                printf("Memory allocation failed\n");
                return -1;
            }

            if (read_file_data(mc, filename, phdr.p_offset, seg_data, phdr.p_filesz) < 0) {
                printf("Failed to read segment data\n");
                free(seg_data);
                return -1;
            }

            memcpy(mc->memory + phdr.p_vaddr, seg_data, phdr.p_filesz);
            free(seg_data);

            if (phdr.p_memsz > phdr.p_filesz) {
                memset(mc->memory + phdr.p_vaddr + phdr.p_filesz, 
                       0, phdr.p_memsz - phdr.p_filesz);
            }
        }
    }

    printf("ELF loaded successfully. Entry point: 0x%x\n", ehdr.e_entry);
    return 0;
}

// ================================
// Program Execution
// ================================

int execute_program(Microcontroller *mc) {
    if (!mc->exec_ctx.is_loaded) {
        printf("No program loaded\n");
        return -1;
    }

    printf("Starting program execution...\n");

    handle_syscall(mc, 1, 0, 0, 0); // write(1, "Hello from VM!\n", 15)
    
    printf("Program finished\n");
    return 0;
}

// ================================
// Syscall Handling
// ================================

void handle_syscall(Microcontroller *mc, uint32_t syscall_num, 
                   uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    switch (syscall_num) {
        // write
        case 1: {
            int fd = arg1;
            char *buf = (char*)(mc->memory + arg2);
            size_t count = arg3;
            
            if (fd == 1 || fd == 2) { // stdout/stderr
                for (size_t i = 0; i < count; i++) {
                    putchar(buf[i]);
                }
                fflush(stdout);
            } else {
                const char *filename = "syscall_output.txt";
                FileMetadata *meta = find_file(mc, filename);
                if (!meta) {
                    create_file(mc, filename, 0, 0);
                    meta = find_file(mc, filename);
                }
                
                if (meta) {
                    write_file_data(mc, filename, meta->size, (uint8_t*)buf, count);
                }
            }
            break;
        }
        
        // read
        case 3: {
            int fd = arg1;
            char *buf = (char*)(mc->memory + arg2);
            size_t count = arg3;
            
            if (fd == 0) { // stdin
                const char *msg = "Syscall read not implemented\n";
                memcpy(buf, msg, strlen(msg));
            } else {
                const char *filename = "syscall_input.txt";
                FileMetadata *meta = find_file(mc, filename);
                if (meta) {
                    read_file_data(mc, filename, 0, (uint8_t*)buf, 
                                 count > meta->size ? meta->size : count);
                }
            }
            break;
        }
        
        case 5: {
            const char *filename = (const char*)(mc->memory + arg1);

            *(int*)(mc->memory + arg3) = 100;
            break;
        }

        case 6: {
            break;
        }
        case 45: {
            *(uint32_t*)(mc->memory + arg1) = mc->size;
            break;
        }
        
        default:
            printf("Unsupported syscall: %d\n", syscall_num);
    }
}

// ================================
// Snapshot Functions
// ================================

// save vm stat to file
int save_snapshot(Microcontroller *mc, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Error opening file");
        return -1;
    }

    if (fwrite(&mc->size, sizeof(size_t), 1, f) != 1) goto write_error;

    if (fwrite(mc->memory, 1, mc->size, f) != mc->size) goto write_error;

    if (fwrite(mc->dir_stack, sizeof(uint32_t), MAX_DIR_DEPTH, f) != MAX_DIR_DEPTH) goto write_error;

    if (fwrite(&mc->dir_stack_ptr, sizeof(uint8_t), 1, f) != 1) goto write_error;

    if (fwrite(&mc->total_file_bytes, sizeof(uint32_t), 1, f) != 1) goto write_error;
    
    fclose(f);
    return 0;

write_error:
    perror("Write error");
    fclose(f);
    return -1;
}

// load vm
int restore_snapshot(Microcontroller *mc, const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Error opening file");
        return -1;
    }

    size_t new_size;
    if (fread(&new_size, sizeof(size_t), 1, f) != 1) goto read_error;
    
    size_t min_size = calculate_min_metadata_memory();
    if (new_size < min_size) {
        printf("Error: Snapshot memory size too small (%zu < %zu)\n", new_size, min_size);
        fclose(f);
        return -1;
    }

    uint8_t *new_memory = malloc(new_size);
    if (!new_memory) {
        perror("Memory allocation failed");
        fclose(f);
        return -1;
    }

    if (fread(new_memory, 1, new_size, f) != new_size) goto read_error;

    uint32_t new_dir_stack[MAX_DIR_DEPTH];
    if (fread(new_dir_stack, sizeof(uint32_t), MAX_DIR_DEPTH, f) != MAX_DIR_DEPTH) goto read_error;

    uint8_t new_dir_stack_ptr;
    if (fread(&new_dir_stack_ptr, sizeof(uint8_t), 1, f) != 1) goto read_error;

    uint32_t new_total_file_bytes;
    if (fread(&new_total_file_bytes, sizeof(uint32_t), 1, f) != 1) goto read_error;

    free(mc->memory);
    mc->memory = new_memory;
    mc->size = new_size;
    memcpy(mc->dir_stack, new_dir_stack, sizeof(uint32_t) * MAX_DIR_DEPTH);
    mc->dir_stack_ptr = new_dir_stack_ptr;
    mc->total_file_bytes = new_total_file_bytes;

    fclose(f);
    return 0;

read_error:
    perror("Read error");
    fclose(f);
    free(new_memory);
    return -1;
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
    
    // Directory stack
    total += MAX_DIR_DEPTH * sizeof(uint32_t);
    
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
    uint32_t active_used = metadata_size + mc->total_file_bytes;
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
    uint32_t active_used = metadata_size + mc->total_file_bytes;
    uint32_t free_space = mc->size - free_ptr;
    float usage_percent = (active_used * 100.0) / mc->size;
    
    printf("===============Memory information===============\n");
    printf("  Total memory:      %10zu bytes\n", mc->size);
    printf("  Total memory:      %s\n", bytes_to_human_readable(mc->size));
    printf("  Metadata:          %10u bytes\n", metadata_size);
    printf("  File data:         %10u bytes\n", mc->total_file_bytes);
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
            printf("  %s%-20s %-9s %u bytes\n", 
                   meta->is_dir ? "[D] " : "[F] ",
                   meta->name, 
                   meta->is_dir ? "DIR" : "FILE",
                   meta->size);
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
    
    return 0;
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
    printf("|   load      - Load external file        |\n");
    printf("|   loadbin  - Load binary program        |\n");
    printf("|   exec     - Execute loaded program     |\n");
    printf("|   syscall  - Test syscall               |\n");
    printf("|   mem       - Memory information        |\n");
    printf("|   man       - Command manual            |\n");
    printf("|   clear     - clear screen              |\n");
    printf("|   snapshot  - Save VM state             |\n");
    printf("|   restore   - Restore VM state          |\n");
    printf("|   exit      - Exit                      |\n");
    printf("===========================================\n");
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
    else if (strcmp(cmd, "snapshot") == 0) {
        printf("snapshot: Save VM state to file\n");
        printf("Usage: snapshot <filename.mvms>\n");
        printf("Example: snapshot backup.mvms\n");
    }
        if (strcmp(cmd, "loadbin") == 0) {
        printf("loadbin: Load ELF binary for execution\n");
        printf("Usage: loadbin <filename>\n");
    }
    else if (strcmp(cmd, "exec") == 0) {
        printf("exec: Execute loaded binary program\n");
        printf("Usage: exec\n");
    }
    else if (strcmp(cmd, "syscall") == 0) {
        printf("syscall: Test syscall handling\n");
        printf("Usage: syscall <num> <arg1> <arg2> <arg3>\n");
    }
    else if (strcmp(cmd, "restore") == 0) {
        printf("restore: Restore VM state from file\n");
        printf("Usage: restore <filename.mvms>\n");
        printf("Example: restore backup.mvms\n");
    }
    else if (strcmp(cmd, "rm") == 0) {
        printf("rm: Delete file or directory\n");
        printf("Usage: rm <filename>\n");
        printf("Note: Directory must be empty\n");
    }
    else if (strcmp(cmd, "load") == 0) {
        printf("load: Load external file into system\n");
        printf("Usage: load <external_path> <internal_name>\n");
        printf("Example: load /home/user/file.txt doc\n");
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
    else {
        printf("No manual for: %s\n", cmd);
        printf("Available commands: ls, mkdir, cd, create, write, read, rm, load, mem, man, clear, exit\n");
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
    if (strcmp(command, "loadbin") == 0 && argc >= 2) {
        if (load_elf(mc, arg1) == 0) {
            printf("Binary '%s' loaded\n", arg1);
        } else {
            printf("Failed to load binary\n");
        }
    }
    else if (strcmp(command, "exec") == 0) {
        if (execute_program(mc) == 0) {
            printf("Program executed\n");
        } else {
            printf("Execution failed\n");
        }
    }
    else if (strcmp(command, "syscall") == 0 && argc >= 5) {
        uint32_t num = atoi(arg1);
        uint32_t a1 = atoi(arg2);
        uint32_t a2 = atoi(arg3);
        uint32_t a3 = atoi(arg4);
        
        handle_syscall(mc, num, a1, a2, a3);
        printf("Syscall %d executed\n", num);
    }
    else if (strcmp(command, "cd") == 0 && argc >= 2) {
        if (change_directory(mc, arg1) == 0) {
            printf("Directory changed\n");
        } else {
            printf("Directory not found\n");
        }
    }
    else if (strcmp(command, "snapshot") == 0 && argc >= 2) {
        if (save_snapshot(mc, arg1) == 0) {
            printf("Snapshot saved to '%s'\n", arg1);
        } else {
            printf("Failed to save snapshot\n");
        }
    }
    else if (strcmp(command, "restore") == 0 && argc >= 2) {
        if (restore_snapshot(mc, arg1) == 0) {
            printf("Snapshot restored from '%s'\n", arg1);
        } else {
            printf("Failed to restore snapshot\n");
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
    else if (strcmp(command, "man") == 0 && argc >= 2) {
        show_manual(arg1);
    }
    else if (strcmp(command, "exit") == 0) {
        printf("Exiting...\n");
        printf("\033[2J\033[H");
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

    while (1) {
        printf("================================================================\n");
        printf("| Microcontroller OS - Memory Configuration                    |\n");
        printf("================================================================\n");
        printf("| type 'exit' for cansel                                       |\n");
        printf("| Minimum required memory: %-8zu bytes (%s)          |\n", 
               min_need_memory, bytes_to_human_readable(min_need_memory));
        printf("| Default memory size:    %-8d bytes (%s)          |\n", 
               DEFAULT_MEMORY_SIZE, bytes_to_human_readable(DEFAULT_MEMORY_SIZE));
        printf("|                                                              |\n");
        printf("| Enter memory size in bytes or press Enter for default:        |\n");
        printf("================================================================\n");
        
        printf("memory_size> ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        
        if (strlen(input) == 0) {
            memory_size = DEFAULT_MEMORY_SIZE;
            break;
        } 
        
        if (!strcmp(input, "exit")) {
            printf("\033[2J\033[H");
            return 0;
        }
        
        if (!atoi(input)) {
            printf("-----------------ERROR-----------------\n");
            printf("type only nums for sellect memory size\n");
            printf("---------------------------------------\n");
            continue;
        }
        
        else {
            memory_size = atol(input);
            if (memory_size < min_need_memory) {
                printf("Error: Memory size must be at least %zu bytes\n", min_need_memory);
                return 1;
            }
            break;
        }
    }

    Microcontroller *mcu = create_microcontroller(memory_size);
    if (!mcu) {
        printf("ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR\n");
        printf("Failed to initialize microcontroller!\n");
        printf("ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR\n");
        printf("\033[2J\033[H");
        return 1;
    }
    
    printf("\nMicrocontroller OS initialized with %zu bytes of memory\n", memory_size);
    printf("Type 'help' for command list\n\n");
    
    while (1) {
        printf("mcuOS> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';
        
        if (strlen(input) > 0) {
            process_command(mcu, input);
        }
    }

    printf("\033[2J\033[H");
    destroy_microcontroller(mcu);
    return 0;
}
