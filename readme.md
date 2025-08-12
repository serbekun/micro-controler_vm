# Microcontroller OS

## How was created code
the code was written during training that's why it's so shitty and have not work places.

## Overview

This project implements a **virtual microcontroller OS** in C that simulates a complete embedded system environment with:

- Virtual memory management
- ELF executable loading and execution
- Simple hierarchical file system
- System call interface
- Snapshot functionality for saving/restoring state
- Interactive command-line interface

## Key Features

### 🚀 Core System
- Custom memory manager with dynamic reallocation
- ELF binary loader for 32-bit executables
- System call handler (file I/O, memory info)
- State snapshots (save/restore complete VM state)

### 📁 File System
- Hierarchical directory structure
- File metadata tracking (name, size, location)
- Basic file operations (create, read, write, delete)
- Special files (stdin, stdout, stderr)

### 💻 Command Line Interface
- File management commands (ls, mkdir, cd, create, etc.)
- Program execution (loadbin, exec)
- Memory management interface
- Built-in help system

## Memory Architecture

| Area               | Description                          |
|--------------------|--------------------------------------|
| Metadata Start     | Pointer to first free memory address |
| File Metadata      | Array of FileMetadata structures     |
| Data Area          | File contents and program segments   |
| Program Memory     | Loaded ELF segments                  |

Default memory size: 4MB (configurable at startup)

## System Calls

| Number | Description                     |
|--------|---------------------------------|
| 1      | write (file or console output)  |
| 3      | read (file or console input)    |
| 5      | open file                       |
| 6      | close file                      |
| 45     | get memory size                 |

## CLI Commands

### File Operations

ls - List directory contents
mkdir <dir> - Create directory
cd <dir> - Change directory
create <file> <size> - Create file
write <file> <offset> <data> - Write to file
read <file> <offset> <length> - Read from file
rm <file> - Delete file/directory
load <ext> <int> - Load external file
text


### Program Execution

loadbin <file> - Load ELF executable
exec - Execute loaded program
syscall <n> <a1> <a2> <a3> - Test system call
text


### System Management

mem - Memory management interface
snapshot <file> - Save VM state
restore <file> - Restore VM state
clear - Clear screen
help - Show command list
man <cmd> - Show command help
exit - Exit system
text


## Building and Running

```bash
gcc -o mcu_os main.c
./mcu_os
```

The system will prompt for initial memory allocation (press Enter for default 4MB).
Example Session

bash

mcuOS> mkdir test
mcuOS> cd test
mcuOS> create hello.txt 32
mcuOS> write hello.txt 0 "Hello World!"
mcuOS> read hello.txt 0 12
Hello World!
mcuOS> loadbin program.elf
mcuOS> exec
Program output...
mcuOS> snapshot backup.mvms

Future Enhancements

    Add process management

    Implement more system calls

    Add support for dynamic linking

    Improve error handling

    Add networking support

Key improvements from the previous version:
1. Better organization of features
2. Updated system call table
3. Added new commands (snapshot/restore)
4. More detailed memory architecture description
5. Cleaner formatting and structure
6. Added example session
7. Removed outdated features no longer in the code

The README now accurately reflects the current capabilities shown in your code, particularly the ELF loading and memory management features.

