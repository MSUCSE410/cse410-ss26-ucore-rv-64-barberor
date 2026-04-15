#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

// we change the ptr to va, so its not a pointer anymore
// before in proj 1, the user passed ptrs to phys addrs
uint64 sys_gettimeofday(uint64 va, int _tz)
{
    struct proc *p = curr_proc();
	// here we translate the va ourselves to physical addr
	// useraddr finds phys addr from the VA passed in
    TimeVal *pa = (TimeVal *)useraddr(p->pagetable, va);
    // va invalid
    if (pa == 0)
        return -1;
    uint64 cycle = get_cycle();
    pa->sec = cycle / CPU_FREQ; // now we are using our phys addr to write tos
    pa->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	// we use microseconds as specified in TimeVal struct (stddef.h)
    return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/
uint64 sys_task_info(uint64 va)
{
    struct proc *p = curr_proc();
    struct TaskInfo info;
    info.status = Running;
    info.time = (int)(get_cycle() * 1000 / CPU_FREQ - p->start_time);
    memmove(info.syscall_times, p->syscall_times, sizeof(info.syscall_times));

    // we have a virtual addr, and need phys
    struct TaskInfo *pa = (struct TaskInfo *)useraddr(p->pagetable, va);
    if (pa == 0)
        return -1;
    *pa = info;
    return 0;
}

// mapping btwn VA and physical mem, with specified permissions,
// kernel allocates RAM and installs Page table entries
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
    if (len == 0) // this means there is nothing to map
        return 0;
    if (len > (1ULL << 30)) // over 1GiB limit
        return -1;
    if ((port & ~0x7) != 0) // bits above bit 2 must be 0
        return -1;
    if ((port & 0x7) == 0) // at least one permission bit
        return -1;
    if (start % PGSIZE != 0) // has to be page aligned
        return -1;

    struct proc *p = curr_proc();
    uint64 end = PGROUNDUP(start + len);
    uint64 a = start;

    // make sure none are mapped alrdy
    for (a = start; a < end; a += PGSIZE) {
        if (walkaddr(p->pagetable, a) != 0) // returns 0 if not mapped
            return -1;
    }

	// flags
    int perm = PTE_U; // user accessible
    if (port & 1) perm |= PTE_R; // readable
    if (port & 2) perm |= PTE_W; // writeable
    if (port & 4) perm |= PTE_X; // exe

    // allocating/map phys page per virtual page
    for (a = start; a < end; a += PGSIZE) {
        void *pa = kalloc(); // get a free phys page, 
        if (pa == 0)
            return -1;
        memset(pa, 0, PGSIZE); // and zero it out
        if (mappages(p->pagetable, a, PGSIZE, (uint64)pa, perm) != 0) {
            kfree(pa); // we free the page if it mapping doesnt work 
            return -1;
        }
    }
    return 0;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	// same as mmap checks
    if (len == 0)
        return 0;
    if (start % PGSIZE != 0)
        return -1;

    struct proc *p = curr_proc();
    uint64 end = PGROUNDUP(start + len);

    // make sure they are mapped AND in range
    for (uint64 a = start; a < end; a += PGSIZE) {
        if (walkaddr(p->pagetable, a) == 0) // 0 = not mapped
            return -1;
    }

	// here we do removing mappings and free the phys pages
    uvmunmap(p->pagetable, start, (end - start) / PGSIZE, 1);
	// the 1 means to call kfree on phys page as it removes the map
    return 0;
}



uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

// PROJECT 3
// process creation
// for spawning it is a fork and exec in a call
uint64 sys_spawn(uint64 va)
{
    struct proc *p = curr_proc();
    char name[200];
    copyinstr(p->pagetable, name, va, 200);

    // new process, load the program into it
    struct proc *np = allocproc();
    if (np == 0)
        return -1;

    int id = get_id_by_name(name);
    if (id < 0) {
        freeproc(np);
        return -1;
    }

    if (loader(id, np) < 0) {
        freeproc(np);
        return -1;
    }

    // set parent mark runnable and return child pid
    np->parent = p;
    np->state = RUNNABLE;
    return np->pid;
}

// pROJECT 3
// prority has to be >= to 2 (from slides)
// sets priority on curr proc and returns
// priroty
uint64 sys_set_priority(long long prio)
{
    if (prio < 2)
        return -1;
    struct proc *p = curr_proc();
    p->priority = prio;
    return prio;
}


extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	
    if (id > 0 && id < MAX_SYSCALL_NUM)
        curr_proc()->syscall_times[id]++;
           
    switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
    case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
    	ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
    	break;
	case SYS_munmap:
    	ret = sys_munmap(args[0], args[1]);
    	break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
    case SYS_setpriority:
        ret = sys_set_priority(args[0]);
        break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
