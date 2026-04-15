#ifndef PROC_H
#define PROC_H

#include "riscv.h"
#include "types.h"

#define NPROC (512)
#define FD_BUFFER_SIZE (16)

struct file;

// Saved registers for kernel context switches.
struct context {
	uint64 ra;
	uint64 sp;

	// callee-saved
	uint64 s0;
	uint64 s1;
	uint64 s2;
	uint64 s3;
	uint64 s4;
	uint64 s5;
	uint64 s6;
	uint64 s7;
	uint64 s8;
	uint64 s9;
	uint64 s10;
	uint64 s11;
};

enum procstate { UNUSED, USED, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };

// Per-process state
struct proc {
	enum procstate state; // Process state
	int pid; // Process ID
	pagetable_t pagetable; // User page table
	uint64 ustack; // Virtual address of kernel stack
	uint64 kstack; // Virtual address of kernel stack
	struct trapframe *trapframe; // data page for trampoline.S
	struct context context; // swtch() here to run process
	uint64 max_page;
	struct proc *parent; // Parent process
	uint64 exit_code;
	struct file *files
		[FD_BUFFER_SIZE]; //File descriptor table, using to record the files opened by the process
	uint64 start_time;
	uint32 syscall_times[500];
	uint64 stride;
	long long priority;
};

#define MAX_SYSCALL_NUM 500

typedef enum {
    UnInit = 0,
    Ready = 1,
    Running = 2,
    Exited = 3,
} TaskStatus;

struct TaskInfo {
    TaskStatus status;
    unsigned int syscall_times[MAX_SYSCALL_NUM];
    int time;
};

#define STAT_DIR  0x040000
#define STAT_FILE 0x100000

typedef struct {
    uint64 dev;
    uint64 ino;
    uint32 mode;
    uint32 nlink;
    uint64 pad[7];
} Stat;



int cpuid();
struct proc *curr_proc();
void exit(int);
void proc_init();
void scheduler() __attribute__((noreturn));
void freeproc(struct proc *);
void sched();
void yield();
int fork();
int exec(char *, char **);
int wait(int, int *);
void add_task(struct proc *);
struct proc *pop_task();
struct proc *allocproc();
int fdalloc(struct file *);
int init_stdio(struct proc *);
int push_argv(struct proc *, char **);
// swtch.S
void swtch(struct context *, struct context *);

#endif // PROC_H