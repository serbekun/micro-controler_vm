#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define MEMORY_SIZE (4 * 1024) // 4 kilobytes of memory
#define METADATA_START 0
#define DATA_START (sizeof(uint32_t))
#define MAX_FILES 32              
#define MAX_TASKS 8
#define STACK_SIZE 1024
#define MAX_DIR_DEPTH 8
#define MAX_OPEN_FILES 32
#define MAX_FILENAME_LEN 31
#define MAX_PATH_LEN 255

// CPU registers
typedef struct {
    uint32_t pc;       // Program counter
    uint32_t sp;       // Stack pointer
    uint32_t regs[16]; // General purpose registers R0-R15
    uint32_t status;   // Status register
} CPUState;

// Task structure
typedef struct {
    CPUState cpu;
    uint32_t stack_start;
    uint32_t stack_size;
    uint8_t active;
    uint8_t priority;
} Task;

// File metadata
typedef struct {
    char name[MAX_FILENAME_LEN + 1]; // Filename
    uint32_t start;    // Data start address or directory ID
    uint32_t size;     // File size
    uint8_t used;      // Usage flag
    uint8_t is_dir;    // Directory flag
    uint32_t parent;   // Parent directory ID
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
    uint8_t current_task;
    Syscall syscall;
    uint32_t dir_stack[MAX_DIR_DEPTH];
    uint8_t dir_stack_ptr;
    uint32_t total_file_bytes;  // File memory usage counter
} Microcontroller;

// Function prototypes
void init_cpu(CPUState *cpu);
int execute_instruction(Microcontroller *mc);
void handle_syscall(Microcontroller *mc);

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

    // Initialize CPU
    init_cpu(&mc->cpu);
    
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

    return mc;
}

// Free microcontroller resources
void destroy_microcontroller(Microcontroller *mc) {
    if (mc) {
        free(mc->memory);
        free(mc);
    }
}

void realoc_microcontroller_memory(Microcontroller *mc) {
    
}

// Write byte to memory
void write_byte(Microcontroller *mc, uint32_t addr, uint8_t value) {
    if (addr < mc->size) mc->memory[addr] = value;
}

// show cuurent directory
void show_current_directory(Microcontroller *mc) {
    printf("now directory %ls\n", mc->dir_stack);
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
                meta->start = i; // Use index as directory ID
            } else {
                meta->start = free_ptr;
                mc->total_file_bytes += size;  // Track memory usage
            }
            
            meta->size = size;
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

// Write data to file
int write_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *data, uint32_t len) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    if (offset > meta->size || offset + len > meta->size) return -1;
    
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
    for (int i = 0; i < MAX_FILES; i++) {
        FileMetadata *meta = get_metadata_slot(mc, i);
        if (meta && meta->used && meta->parent == current_dir) {
            printf("  %s%s: %s, size=%u bytes\n", 
                   meta->is_dir ? "[D] " : "[F] ",
                   meta->name, 
                   meta->is_dir ? "DIRECTORY" : "FILE",
                   meta->size);
        }
    }
}

// Change directory
int change_directory(Microcontroller *mc, const char *dirname) {
    if (!strcmp(dirname, "..")) {
        if (mc->dir_stack_ptr > 0) {
            mc->dir_stack_ptr--;
            return 0;
        }
        return -1;
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
            
            // Allocate stack
            task->stack_start = free_ptr;
            task->stack_size = STACK_SIZE;
            *((uint32_t *)(mc->memory + METADATA_START)) = free_ptr + STACK_SIZE;
            
            // Initialize CPU state
            init_cpu(&task->cpu);
            task->cpu.pc = meta->start;
            task->cpu.sp = free_ptr + STACK_SIZE - 4;
            
            // Initialize stack with zeros
            memset(mc->memory + free_ptr, 0, STACK_SIZE);
            
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
                break;
            }
        }
        
        task->cpu = mc->cpu;
        mc->cpu = saved_cpu;
    }
}

// Load external file
int load_external_file(Microcontroller *mc, const char *ext_path, const char *int_name) {
    FILE *f = fopen(ext_path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0) {
        fclose(f);
        return -1;
    }
    
    uint8_t *buffer = malloc(size);
    if (!buffer) {
        fclose(f);
        return -1;
    }
    
    if (fread(buffer, 1, size, f) != (size_t)size) {
        free(buffer);
        fclose(f);
        return -1;
    }
    fclose(f);
    
    // Delete old file if exists
    FileMetadata *old = find_file(mc, int_name);
    if (old) delete_file(mc, int_name);
    
    if (create_file(mc, int_name, size, 0) < 0) {
        free(buffer);
        return -1;
    }
    
    int result = write_file_data(mc, int_name, 0, buffer, size);
    free(buffer);
    
    return result;
}

// ================================
// CPU Implementation
// ================================

// Initialize CPU
void init_cpu(CPUState *cpu) {
    memset(cpu, 0, sizeof(CPUState));
    cpu->sp = MEMORY_SIZE - 4;  // Set to top of memory
}

// Handle system calls
void handle_syscall(Microcontroller *mc) {
    Syscall *sc = &mc->syscall;
    sc->return_value = 0;
    
    switch(sc->syscall_num) {
        case 0: // Exit
            if (mc->current_task != 0) {
                mc->tasks[mc->current_task].active = 0;
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
            
        default:
            printf("Unknown instruction: 0x%02X\n", opcode);
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
    printf("|   task      - Create task               |\n");
    printf("|   load      - Load external file        |\n");
    printf("|   mem       - Memory information        |\n");
    printf("|   man       - Command manual            |\n");
    printf("|   exit      - Exit                      |\n");
    printf("|   makeprog  - Create test program       |\n");
    printf("|   writeinst - Write instruction         |\n");
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
    
    printf("Test program written to test.bin (20 bytes)\n");
    printf("Execute: run test.bin\n");
}

// Show command manual
void show_manual(const char *cmd) {
    if (!strcmp(cmd, "ls")) {
        printf("ls: Show files in current directory\n");
        printf("Usage: ls\n");
    } 
    else if (!strcmp(cmd, "pwd")) {
        printf("pwd: show current directory");
    }
    else if (!strcmp(cmd, "mkdir")) {
        printf("mkdir: Create new directory\n");
        printf("Usage: mkdir <directory_name>\n");
    }
    else if (!strcmp(cmd, "cd")) {
        printf("cd: Change current directory\n");
        printf("Usage: cd <directory_name>\n");
        printf("       cd ..  (go to parent directory)\n");
    }
    else if (!strcmp(cmd, "create")) {
        printf("create: Create new file\n");
        printf("Usage: create <filename> <size_in_bytes>\n");
    }
    else if (!strcmp(cmd, "write")) {
        printf("write: Write data to file\n");
        printf("Usage: write <file> <offset> <data>\n");
        printf("Example: write hello.txt 0 \"Hello world\"\n");
    }
    else if (!strcmp(cmd, "read")) {
        printf("read: Read data from file\n");
        printf("Usage: read <file> <offset> <length>\n");
        printf("Example: read hello.txt 0 11\n");
    }
    else if (!strcmp(cmd, "rm")) {
        printf("rm: Delete file or directory\n");
        printf("Usage: rm <filename>\n");
        printf("Note: Directory must be empty\n");
    }
    else if (!strcmp(cmd, "run")) {
        printf("run: Execute program\n");
        printf("Usage: run <program_file>\n");
    }
    else if (!strcmp(cmd, "task")) {
        printf("task: Create new task\n");
        printf("Usage: task <file> <priority>\n");
        printf("Priority: 0 (lowest) to 255 (highest)\n");
    }
    else if (!strcmp(cmd, "load")) {
        printf("load: Load external file into system\n");
        printf("Usage: load <external_path> <internal_name>\n");
        printf("Example: load /home/user/program.bin app\n");
    }
    else if (!strcmp(cmd, "mem")) {
        printf("mem: Show memory usage\n");
        printf("Usage: mem\n");
    }
    else if (!strcmp(cmd, "man")) {
        printf("man: Command manual\n");
        printf("Usage: man <command_name>\n");
        printf("Example: man create\n");
    }
    else if (!strcmp(cmd, "exit")) {
        printf("exit: Exit system\n");
        printf("Usage: exit\n");
    }
    else if (!strcmp(cmd, "makeprog")) {
        printf("makeprog: Create test program\n");
        printf("Usage: makeprog\n");
    }
    else if (!strcmp(cmd, "writeinst")) {
        printf("writeinst: Write instruction to file\n");
        printf("Usage: writeinst <file> <offset> <opcode_hex> <reg1> <reg2> <reg3> <imm>\n");
        printf("Example: writeinst program.bin 0 01 0 0 0 42   # MOV R0, #42\n");
    }
    else {
        printf("No manual for: %s\n", cmd);
        printf("Available commands: ls, mkdir, cd, create, write, read, rm, run, task, load, mem, man, exit, makeprog, writeinst\n");
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
    
    if (!strcmp(command, "ls") || !strcmp(command, "dir")) {
        list_files(mc);
    }
    else if (!strcmp(command, "mkdir")&& argc >= 2) {
        if (create_file(mc, arg1, 0, 1) >= 0) {
            printf("Directory '%s' created\n", arg1);
        } else {
            printf("Error creating directory\n");
        }
    }
    else if (!strcmp(command, "pwd")) {
        show_current_directory(mc);
    }
    else if (!strcmp(command, "cd") && argc >= 2) {
        if (!change_directory(mc, arg1)) {
            printf("Directory changed\n");
        } else {
            printf("Directory not found\n");
        }
    }
    else if (!strcmp(command, "create") && argc >= 3) {
        uint32_t size = atoi(arg2);
        if (create_file(mc, arg1, size, 0) >= 0) {
            printf("File '%s' created (%u bytes)\n", arg1, size);
        } else {
            printf("Error creating file\n");
        }
    }
    else if (!strcmp(command, "write") && argc >= 4) {
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
    else if (strcmp(command, "task") == 0 && argc >= 3) {
        uint8_t priority = atoi(arg2);
        int task_id = create_task(mc, arg1, priority);
        if (task_id >= 0) {
            printf("Task created (ID: %d)\n", task_id);
        } else {
            printf("Error creating task\n");
        }
    }
    else if (strcmp(command, "load") == 0 && argc >= 3) {
        if (load_external_file(mc, arg1, arg2) == 0) {
            printf("File '%s' loaded as '%s'\n", arg1, arg2);
        } else {
            printf("Load error\n");
        }
    }
    else if (strcmp(command, "mem") == 0) {
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
        
        printf("\nMemory information:\n");
        printf("  Total memory:      %lu bytes\n", mc->size);
        printf("  Metadata:          %u bytes\n", metadata_size);
        printf("  File data:         %u bytes\n", mc->total_file_bytes);
        printf("  Task stacks:       %u bytes\n", stack_usage);
        printf("  Total used:        %u bytes\n", active_used);
        printf("  Allocated:         %u bytes\n", free_ptr);
        printf("  Free:              %u bytes\n", free_space);
        printf("  Usage:             %.1f%%\n\n", 
               (active_used * 100.0) / mc->size);
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
    Microcontroller *mcu = create_microcontroller(MEMORY_SIZE);
    char input[256];
    
    printf("Microcontroller operating system initialized\n");
    printf("Type 'help' for command list\n\n");
    
    // Create system directories
    create_file(mcu, "bin", 0, 1);
    create_file(mcu, "lib", 0, 1);
    create_file(mcu, "home", 0, 1);
    
    while (1) {
        printf("mcuOS> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;
        
        if (strcmp(input, "run_tasks") == 0) {
            scheduler(mcu);
            execute_current_task(mcu);
        } else if (strlen(input) > 0) {
            process_command(mcu, input);
        }
    }
    
    destroy_microcontroller(mcu);
    return 0;
}
