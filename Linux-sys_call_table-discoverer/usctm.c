/*
* 
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* @file usctm.c 
* @brief This is the main source for the Linux Kernel Module which implements
* 	 the runtime discovery of the syscall table position and of free entries (those 
* 	 pointing to sys_ni_syscall) 
*
* @author Francesco Quaglia
*
* @date November 22, 2020
* @updated October 2, 2024
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include "./include/vtpmo.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("USCTM");


#define MODNAME "USCTM"


extern int sys_vtpmo(unsigned long vaddr);

#define ADDRESS_MASK 0xfffffffffffff000//to migrate

#define START 			0xffffffff00000000ULL		// use this as starting address --> this is a biased search since does not start from 0xffff000000000000
#define MAX_ADDR		0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL	134
#define SECOND_NI_SYSCALL	174
#define THIRD_NI_SYSCALL	182 
#define FOURTH_NI_SYSCALL	183
#define FIFTH_NI_SYSCALL	214	
#define SIXTH_NI_SYSCALL	215	
#define SEVENTH_NI_SYSCALL	236	

#define ENTRIES_TO_EXPLORE 256

//avoid compiler warnings with the below prototypes
int good_area(unsigned long *);
int validate_page(unsigned long *);
void syscall_table_finder(void);


unsigned long *hacked_ni_syscall=NULL;
unsigned long **hacked_syscall_tbl=NULL;

unsigned long sys_call_table_address = 0x0;
module_param(sys_call_table_address, ulong, 0660);

unsigned long sys_ni_syscall_address = 0x0;
module_param(sys_ni_syscall_address, ulong, 0660);


int good_area(unsigned long * addr){
	int i;
	for(i=1;i<FIRST_NI_SYSCALL;i++){
		//controlla se gli indirizzi iniziali nella syscall table sono tutti diversi dall'indirizzo di ni_syscall
		if(addr[i] == addr[FIRST_NI_SYSCALL]) goto bad_area;
	}	
	return 1;
bad_area:
	return 0;
}

/* This routine checks if the page contains the begin of the syscall_table.  */
int validate_page(unsigned long *addr){
	int i = 0;
	unsigned long page 	= (unsigned long) addr;
	unsigned long new_page 	= (unsigned long) addr;
	for(; i < PAGE_SIZE; i+=sizeof(void*)){
		//verifico se l'i-esima entry cade nella stessa pagina o in una nuova pagina (che devo verificare se è mappata con sys_vtpmo)
		new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);
			
		// If the table occupies 2 pages check if the second one is materialized in a frame
		if( 
			( (page+PAGE_SIZE) == (new_page & ADDRESS_MASK) )
			&& sys_vtpmo(new_page) == NO_MAP
		) 
			break;
		// go for patter matching
		addr = (unsigned long*) (page+i);
		if(
			   ( (addr[FIRST_NI_SYSCALL] & 0x3  ) == 0 )		
			   && (addr[FIRST_NI_SYSCALL] != 0x0 )			// not points to 0x0	
			   && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 )	// not points to a locatio lower than 0xffffffff00000000	
	//&& ( (addr[FIRST_NI_SYSCALL] & START) == START ) 	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]	 )	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL] )	
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL] )	
			&&   (good_area(addr))
		){
			hacked_ni_syscall = (void*)(addr[FIRST_NI_SYSCALL]);				// save ni_syscall
			sys_ni_syscall_address = (unsigned long)hacked_ni_syscall;
			hacked_syscall_tbl = (void*)(addr);				// save syscall_table address
			sys_call_table_address = (unsigned long) hacked_syscall_tbl;
			return 1;
		}
	}
	return 0;
}

/* This routine looks for the syscall table.  */
void syscall_table_finder(void){
	unsigned long k; // current page
	unsigned long candidate; // current page

	for(k=START; k < MAX_ADDR; k+=4096){	
		candidate = k;
		if((sys_vtpmo(candidate) != NO_MAP)){
			// check if candidate maintains the syscall_table
			if(validate_page( (unsigned long *)(candidate)) ){
				printk("%s: syscall table found at %px\n",MODNAME,(void*)(hacked_syscall_tbl));
				printk("%s: sys_ni_syscall found at %px\n",MODNAME,(void*)(hacked_ni_syscall));
				break;
			}
		}
	}
	
}


#define MAX_FREE 15
int free_entries[MAX_FREE];
module_param_array(free_entries,int,NULL,0660);//default array size already known - here we expose what entries are free


#define SYS_CALL_INSTALL

#ifdef SYS_CALL_INSTALL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) 
#define INST_LEN 5
char jump_inst[INST_LEN];
unsigned long x64_sys_call_addr;
int offset;
//Non vado a registrate un handler per questa krpobe perchè mi serve solo per sapere l'indirizzo di questo simbolo
//Quando registro la kprobe infatti il kernel colloca nel campo addr della struct krpobe l'indirizzo del simbolo
static struct kprobe kp_x64_sys_call = { .symbol_name = "x64_sys_call" };

//stuff here is using retpoline
//Questa call è invocata tutte le volte che si invoca una syscall (perchè si passa per x64_sys_call)
//questa call prende l'indice della syscall da invocare, si spiazza a partite dalla base della tabella (hacked_syscall_tbl) e invoca la syscall
//L'indirizzo della syscall da invocare è messo in rax, l'istruzione di jmp salta a questo indirizzo
static inline void call(struct pt_regs *regs, unsigned int nr){
    	asm volatile("mov (%1, %0, 8), %%rax\n\t"
             "jmp __x86_indirect_thunk_rax\n\t"
             :
             : "r"((long)nr), "r"(hacked_syscall_tbl)
             : "rax");
}

#endif


unsigned long cr0, cr4;

static inline void write_cr0_forced(unsigned long val){
        unsigned long __force_order;
        asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void){
        write_cr0_forced(cr0);
}

static inline void unprotect_memory(void){
        write_cr0_forced(cr0 & ~X86_CR0_WP);
}

static inline void write_cr4_forced(unsigned long val){
        unsigned long __force_order;
        asm volatile("mov %0, %%cr4" : "+r"(val), "+m"(__force_order));
}

static inline void conditional_cet_disable(void){
#ifdef X86_CR4_CET
        if (cr4 & X86_CR4_CET)
                write_cr4_forced(cr4 & ~X86_CR4_CET);
#endif
}

static inline void conditional_cet_enable(void){
#ifdef X86_CR4_CET
        if (cr4 & X86_CR4_CET)
                write_cr4_forced(cr4);
#endif
}
// Disabilita la protezione che impedisce di modificare le pagine read-only, come la syscall table
static inline void begin_syscall_table_hack(void){
        preempt_disable();
        cr0 = read_cr0();
        cr4 = native_read_cr4();
        conditional_cet_disable();
        unprotect_memory();
}
// Abilita nuovamente la protezione
static inline void end_syscall_table_hack(void){
        protect_memory();
        conditional_cet_enable();
        preempt_enable();
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _trial, unsigned long, A, unsigned long, B){
#else
asmlinkage long sys_trial(unsigned long A, unsigned long B){
#endif

        printk("%s: thread %d requests a trial sys_call with %lu and %lu as parameters\n",MODNAME,current->pid,A,B);

        return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_trial = (unsigned long) __x64_sys_trial;	
#else
#endif


#else
#endif



int init_module(void) {
	
	int i,j;
		
        printk("%s: initializing\n",MODNAME);
	
	syscall_table_finder();

	if(!hacked_syscall_tbl){
		printk("%s: failed to find the sys_call_table\n",MODNAME);
		return -1;
	}

	j=0;
	for(i=0;i<ENTRIES_TO_EXPLORE;i++)
		if(hacked_syscall_tbl[i] == hacked_ni_syscall){
			printk("%s: found sys_ni_syscall entry at syscall_table[%d]\n", MODNAME,i);	
			free_entries[j++] = i;
			if(j>=MAX_FREE) break;
		}

#ifdef SYS_CALL_INSTALL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	if (register_kprobe(&kp_x64_sys_call)) {
                printk(KERN_ERR "%s: cannot register kprobe for x64_sys_call\n", MODNAME);
                return -1;
        }

		//Recupero l'indirizzo di x64_sys_call (che devo patchare per fargli usare la tabella delle syscall invece che lo switch)
        x64_sys_call_addr = (unsigned long)kp_x64_sys_call.addr;
        unregister_kprobe(&kp_x64_sys_call);

        /* JMP opcode */
        jump_inst[0] = 0xE9;
        /* RIP points to the next instruction. Current instruction has length 5 */
        offset = (unsigned long)call - x64_sys_call_addr - INST_LEN;
        memcpy(jump_inst + 1, &offset, sizeof(int));
	
#endif

	begin_syscall_table_hack();
        hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)sys_trial;
	printk("%s: a sys_call with 2 parameters has been installed as a trial on the sys_call_table at displacement %d\n",MODNAME,FIRST_NI_SYSCALL);	

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
//these kernel versions are configured to avoid the usage of the syscall table 
//this piece of code intercepts the activation of the syscall dispatcher and
//redirects control to the function that restores the usage of the syscall table 
//it may be possible that I did not check all the kernel cofigurations
//the user can add here whichever configuration he wants that avoids the
//usage of the syscall table while dispatching syscalls
        memcpy((unsigned char *)x64_sys_call_addr, jump_inst, INST_LEN);
#endif
        end_syscall_table_hack();

#else
#endif

        printk("%s: module correctly mounted\n",MODNAME);

        return 0;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#else
void cleanup_module(void) {
                
#ifdef SYS_CALL_INSTALL
	begin_syscall_table_hack();
        hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)hacked_ni_syscall;
	end_syscall_table_hack();
#else
#endif
        printk("%s: shutting down\n",MODNAME);
        
}
#endif
