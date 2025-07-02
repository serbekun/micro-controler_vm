# Microcontroller OS

## Overview

This project implements a **virtual microcontroller OS** in C that simulates a basic operating system environment with its own:
- Virtual CPU
- Simple file system (supporting files and directories)
- Task management (multitasking support)
- Instruction set (virtual ISA with custom opcodes)
- System calls (file I/O, console I/O, etc.)
- CLI shell interface

It is designed as an educational toy operating system for learning concepts of embedded systems, file systems, and CPU instruction execution.

---

## Features

### ✅ Virtual CPU

- **Registers**: 16 general-purpose registers (`R0`–`R15`), program counter (`pc`), stack pointer (`sp`), and status register.
- **Custom instruction set**:
  - Arithmetic: `MOV`, `ADD`, `SUB`
  - Memory: `LOAD`, `STORE`, `PUSH`, `POP`
  - Control flow: `JMP`, `JZ`, `HALT`
  - System: `SYSCALL`, `DELAY`
- Stack-based function calling support.

### ✅ Virtual File System

- **Files and directories** with metadata stored in simulated memory.
- Supports creating, writing, reading, and deleting files.
- Supports creating directories and navigating between them (`cd`, `ls`).

### ✅ Task Management

- Support for up to 8 tasks (threads) with individual stacks and CPU contexts.
- Simple round-robin scheduler.
- Ability to run programs as background tasks with priorities.

### ✅ System Calls

Implemented system calls:
- File operations (read, write, create)
- Character I/O (print, read from stdin)
- Exit syscall for tasks

### ✅ CLI Shell

Built-in interactive shell supporting commands like:
- `ls` — list files
- `mkdir` — create directory
- `cd` — change directory
- `create` — create file
- `write` — write string to file
- `read` — read data from file
- `rm` — delete file or directory
- `run` — execute a program in foreground
- `task` — create a background task
- `load` — load external file into virtual file system
- `mem` — show memory usage info
- `man` — show command manual
- `exit` — exit shell

---

## Memory Layout

- **Metadata start**: Tracks next free memory pointer.
- **File metadata**: Array of `FileMetadata` structures for files/directories.
- **Data area**: Stores file contents and task stacks.
- **Stack area**: Dynamically allocated per task (default 1KB each).

---

## Example Usage

```bash
mcuOS> mkdir test
mcuOS> cd test
mcuOS> create hello.txt 32
mcuOS> write hello.txt 0 "Hello Microcontroller!"
mcuOS> read hello.txt 0 22
Data from 'hello.txt':
Hello Microcontroller!
mcuOS> mem
```
File Operations

    Create: create <filename> <size>

    Write: write <filename> <offset> <data>

    Read: read <filename> <offset> <length>

    Delete: rm <filename>

    List: ls

    Navigate: cd <dirname>

Task System

    Create a task: task <filename> <priority>

    Scheduler: run_tasks (executes next ready task)

System Calls
Number	Description
0	Exit
2	Read file
3	Write file
4	Create file
0x10	Print character
0x11	Read character
Build & Run

gcc -o mcu_os main.c
./mcu_os

Future Ideas

    Add a simulated interrupt system

    Implement more syscalls (network, timers)

    Add support for binary executable loading

    Improve instruction set

License

MIT License. Free for educational and research use.
Author

[Mishchenko Sergey]
📄 Related Files

    main.c — main implementation file.

    README.md — this documentation.
