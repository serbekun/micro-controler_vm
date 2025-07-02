#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define MEMORY_SIZE (8 * 1024 * 1024) // 8 kilobytes
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

// File metadata structure
typedef struct {
    char name[MAX_FILENAME_LEN + 1]; // Filename
    uint32_t start;    // Data start address or directory ID
    uint32_t size;     // File size
    uint8_t used;      // Usage flag
    uint8_t is_dir;    // Directory flag
    uint32_t parent;   // Parent directory ID
} FileMetadata;

// System call structure
typedef struct {
    uint32_t syscall_num;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;     // Additional argument
    uint32_t return_value;
} Syscall;

typedef struct {
    uint8_t *memory;   
    size_t size;       
    CPUState cpu;
    Task tasks[MAX_TASKS];
    uint8_t current_task;
    Syscall syscall;
    uint32_t dir_stack[MAX_DIR_DEPTH];
    uint8_t dir_stack_ptr;
    uint32_t total_file_bytes;  // Track total file data usage
} Microcontroller;

// Function prototypes
void init_cpu(CPUState *cpu);
int execute_instruction(Microcontroller *mc);
void handle_syscall(Microcontroller *mc);

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

void destroy_microcontroller(Microcontroller *mc) {
    if (mc) {
        free(mc->memory);
        free(mc);
    }
}

void write_byte(Microcontroller *mc, uint32_t addr, uint8_t value) {
    if (addr < mc->size) mc->memory[addr] = value;
}

uint8_t read_byte(Microcontroller *mc, uint32_t addr) {
    return (addr < mc->size) ? mc->memory[addr] : 0xFF;
}

FileMetadata *get_metadata_slot(Microcontroller *mc, int index) {
    if (index < 0 || index >= MAX_FILES) return NULL;
    uint32_t offset = DATA_START + index * sizeof(FileMetadata);
    if (offset + sizeof(FileMetadata) > mc->size) return NULL;
    return (FileMetadata *)(mc->memory + offset);
}

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
                mc->total_file_bytes += size;  // Track file data usage
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

int write_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *data, uint32_t len) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    if (offset > meta->size || offset + len > meta->size) return -1;
    
    for (uint32_t j = 0; j < len; j++) {
        write_byte(mc, meta->start + offset + j, data[j]);
    }
    return 0;
}

int read_file_data(Microcontroller *mc, const char *filename, uint32_t offset, uint8_t *buffer, uint32_t len) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    if (offset > meta->size || offset + len > meta->size) return -1;
    
    for (uint32_t j = 0; j < len; j++) {
        buffer[j] = read_byte(mc, meta->start + offset + j);
    }
    return 0;
}

int delete_file(Microcontroller *mc, const char *filename) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta) return -1;
    
    // If it's a directory, check if it's empty
    if (meta->is_dir) {
        for (int i = 0; i < MAX_FILES; i++) {
            FileMetadata *child = get_metadata_slot(mc, i);
            if (child && child->used && child->parent == meta->start) {
                return -1; // Directory not empty
            }
        }
    } else {
        // Update total file bytes when deleting a file
        mc->total_file_bytes -= meta->size;
    }
    
    meta->used = 0;
    return 0;
}

void list_files(Microcontroller *mc) {
    uint32_t current_dir = mc->dir_stack[mc->dir_stack_ptr];
    
    printf("Current directory contents:\n");
    for (int i = 0; i < MAX_FILES; i++) {
        FileMetadata *meta = get_metadata_slot(mc, i);
        if (meta && meta->used && meta->parent == current_dir) {
            printf("  %s%s: %s, size=%u bytes\n", 
                   meta->is_dir ? "[D] " : "[F] ",
                   meta->name, 
                   meta->is_dir ? "DIR" : "FILE",
                   meta->size);
        }
    }
}

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

int create_task(Microcontroller *mc, const char *filename, uint8_t priority) {
    FileMetadata *meta = find_file(mc, filename);
    if (!meta || meta->is_dir) return -1;
    
    // Find free task slot
    for (int i = 1; i < MAX_TASKS; i++) { // Start from 1, 0 is main thread
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
    
    // If no active tasks, use main
    mc->current_task = 0;
}

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

// Load program from external file
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
// CPU implementation
// ================================

void init_cpu(CPUState *cpu) {
    memset(cpu, 0, sizeof(CPUState));
    cpu->sp = MEMORY_SIZE - 4;  // Set to top of memory
}

// System calls
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
            
        case 3: // Write file
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
            
        case 0x0A: // SYSCALL
            mc->syscall.syscall_num = mc->cpu.regs[0];
            mc->syscall.arg1 = mc->cpu.regs[1];
            mc->syscall.arg2 = mc->cpu.regs[2];
            mc->syscall.arg3 = mc->cpu.regs[3];
            mc->syscall.arg4 = mc->cpu.regs[4];
            handle_syscall(mc);
            break;
            
        case 0xFF: // HALT
            return 0;
            
        default:
            printf("Unknown instruction: 0x%02X\n", opcode);
            return 0;
    }
    
    return 1;
}

// ================================
// Command line interface
// ================================

void show_interface() {
    printf("\n");
    printf("===========================================\n");
    printf("|    Microcontroller OS                   |\n");
    printf("|=========================================|\n");
    printf("| Commands:                               |\n");
    printf("|   ls        - List files                |\n");
    printf("|   mkdir     - Create directory          |\n");
    printf("|   cd        - Change directory          |\n");
    printf("|   create    - Create file               |\n");
    printf("|   write     - Write to file             |\n");
    printf("|   read      - Read file                 |\n");
    printf("|   rm        - Delete file               |\n");
    printf("|   run       - Execute program           |\n");
    printf("|   task      - Create task               |\n");
    printf("|   load      - Load external file        |\n");
    printf("|   mem       - Memory info               |\n");
    printf("|   man       - Show command manual       |\n");
    printf("|   exit      - Exit                      |\n");
    printf("===========================================\n");
}

void show_manual(const char *cmd) {
    if (strcmp(cmd, "ls") == 0) {
        printf("ls: List files in the current directory\n");
        printf("Usage: ls\n");
    } 
    else if (strcmp(cmd, "mkdir") == 0) {
        printf("mkdir: Create a new directory\n");
        printf("Usage: mkdir <directory_name>\n");
    }
    else if (strcmp(cmd, "cd") == 0) {
        printf("cd: Change current directory\n");
        printf("Usage: cd <directory_name>\n");
        printf("       cd ..  (go to parent directory)\n");
    }
    else if (strcmp(cmd, "create") == 0) {
        printf("create: Create a new file\n");
        printf("Usage: create <filename> <size_in_bytes>\n");
    }
    else if (strcmp(cmd, "write") == 0) {
        printf("write: Write data to a file\n");
        printf("Usage: write <filename> <offset> <data_string>\n");
        printf("Example: write hello.txt 0 \"Hello World\"\n");
    }
    else if (strcmp(cmd, "read") == 0) {
        printf("read: Read data from a file\n");
        printf("Usage: read <filename> <offset> <length>\n");
        printf("Example: read hello.txt 0 11\n");
    }
    else if (strcmp(cmd, "rm") == 0) {
        printf("rm: Delete a file or directory\n");
        printf("Usage: rm <filename>\n");
        printf("Note: Directories must be empty to be deleted\n");
    }
    else if (strcmp(cmd, "run") == 0) {
        printf("run: Execute a program\n");
        printf("Usage: run <filename>\n");
    }
    else if (strcmp(cmd, "task") == 0) {
        printf("task: Create a new task to run a program\n");
        printf("Usage: task <filename> <priority>\n");
        printf("Priority: 0 (lowest) to 255 (highest)\n");
    }
    else if (strcmp(cmd, "load") == 0) {
        printf("load: Load an external file into the filesystem\n");
        printf("Usage: load <external_path> <internal_name>\n");
        printf("Example: load /home/user/program.bin app\n");
    }
    else if (strcmp(cmd, "mem") == 0) {
        printf("mem: Show memory usage information\n");
        printf("Usage: mem\n");
    }
    else if (strcmp(cmd, "man") == 0) {
        printf("man: Show manual for a command\n");
        printf("Usage: man <command_name>\n");
        printf("Example: man create\n");
    }
    else if (strcmp(cmd, "exit") == 0) {
        printf("exit: Exit the microcontroller OS\n");
        printf("Usage: exit\n");
    }
    else {
        printf("No manual entry for: %s\n", cmd);
        printf("Available commands: ls, mkdir, cd, create, write, read, rm, run, task, load, mem, man, exit\n");
    }
}

void process_command(Microcontroller *mc, const char *cmd) {
    char command[32], arg1[256], arg2[256], arg3[256];
    int args = sscanf(cmd, "%31s %255s %255s %255s", command, arg1, arg2, arg3);
    
    if (args < 1) return;
    
    if (!strcmp(command, "ls") || !strcmp(command, "dir")) {
        list_files(mc);
    }
    else if (strcmp(command, "mkdir") == 0 && args >= 2) {
        if (create_file(mc, arg1, 0, 1) >= 0) {
            printf("Directory '%s' created\n", arg1);
        } else {
            printf("Error creating directory\n");
        }
    }
    else if (strcmp(command, "cd") == 0 && args >= 2 || !strcmp(command, "touch")) {
        if (change_directory(mc, arg1) == 0) {
            printf("Directory changed\n");
        } else {
            printf("Directory not found\n");
        }
    }
    else if (strcmp(command, "create") == 0 && args >= 3) {
        uint32_t size = atoi(arg2);
        if (create_file(mc, arg1, size, 0) >= 0) {
            printf("File '%s' created (%u bytes)\n", arg1, size);
        } else {
            printf("Error creating file\n");
        }
    }
    else if (strcmp(command, "write") == 0 && args >= 4) {
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
    else if (strcmp(command, "read") == 0 && args >= 4) {
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
    else if (strcmp(command, "rm") == 0 && args >= 2) {
        if (delete_file(mc, arg1) == 0) {
            printf("File '%s' deleted\n", arg1);
        } else {
            printf("Delete error\n");
        }
    }
    else if (strcmp(command, "run") == 0 && args >= 2) {
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
    else if (strcmp(command, "task") == 0 && args >= 3) {
        uint8_t priority = atoi(arg2);
        int task_id = create_task(mc, arg1, priority);
        if (task_id >= 0) {
            printf("Task created (ID: %d)\n", task_id);
        } else {
            printf("Error creating task\n");
        }
    }
    else if (strcmp(command, "load") == 0 && args >= 3) {
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
    
    // Calculate active stack usage
    for (int i = 0; i < MAX_TASKS; i++) {
        if (mc->tasks[i].active) {
            stack_usage += mc->tasks[i].stack_size;
        }
    }
    
    uint32_t active_used = metadata_size + mc->total_file_bytes + stack_usage;
    uint32_t free_space = mc->size - free_ptr;
    
    printf("\nMemory Information:\n");
    printf("  Total memory:      %lu bytes\n", mc->size);
    printf("  Metadata area:     %u bytes\n", metadata_size);
    printf("  Active file data:  %u bytes\n", mc->total_file_bytes);
    printf("  Active stacks:     %u bytes\n", stack_usage);
    printf("  Total active:      %u bytes\n", active_used);
    printf("  Allocated (high):  %u bytes\n", free_ptr);
    printf("  Free space:        %u bytes\n", free_space);
    printf("  Utilization:       %.1f%%\n\n", 
           (active_used * 100.0) / mc->size);
    }
    else if (strcmp(command, "man") == 0 && args >= 2) {
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
        printf("Type 'help' for available commands\n");
    }
}

int main() {
    Microcontroller *mcu = create_microcontroller(MEMORY_SIZE);
    char input[256];
    
    printf("Microcontroller OS initialized\n");
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
