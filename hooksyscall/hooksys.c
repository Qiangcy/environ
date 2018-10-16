#include <asm/unistd.h> 
#include <asm/cacheflush.h> 
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/syscalls.h> 
#include <asm/pgtable_types.h> 
#include <linux/highmem.h> 
#include <linux/fs.h> 
#include <linux/sched.h> 
#include <linux/moduleparam.h> 


#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/desc_defs.h>

//pt_regs
//#include <asm/ptrace.h>
//#include <asm/compat.h>
//vir2phy
#include <asm/page.h>


MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("QCY"); 
/*MY sys_call_table address*/ 
//ffffffff81601680 
void **system_call_table_addr; 
/*my custom syscall that takes process name*/ 
asmlinkage int (*custom_syscall) (char* name);


static unsigned long vaddr2paddr(unsigned long vaddr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t  tmp;
    //unsigned long paddr = 0;
    //unsigned long page_addr = 0;
    //unsigned long page_offset = 0;
    spin_lock(&current->mm->page_table_lock);
    pgd = pgd_offset(current->mm, vaddr);
    printk("pdg_val = 0x%lx\n", pgd_val(*pgd));
    //printk("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }

    pud = pud_offset(pgd, vaddr);
    printk("pud_val = 0x%lx\n", pud_val(*pud));
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    printk("pmd_val = 0x%lx\n", pmd_val(*pmd));
    //printk("pmd_index = %lu\n", pmd_index(vaddr));
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_map(pmd, vaddr);
    printk("pte_val = 0x%lx\n",pte_val(*pte));
    //printk("pte_index = %lu\n", pte_index(vaddr));
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return -1;
    }
/*
    if (pte_val(*pte) != 0){
        tmp = __pte((pte_val(*pte)&~_PAGE_PRESENT));
        set_pte(pte, tmp); 
        return pte_val(*pte);
    }
*/
    if (pte_present(*pte)) {
	tmp = pte_set_flags(*pte, (_AT(pteval_t, 1) << 51));
	//pte_clear(current->mm, vaddr, pte);    	
	//set_pte(pte, tmp);
	*(pte)=tmp;
    }
    spin_unlock(&current->mm->page_table_lock);
    printk("pf new pte_val = 0x%lx\n",pte_val(*pte));
    return 0;
}




static unsigned long setpresent(unsigned long vaddr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t tmp;
    spin_lock(&current->mm->page_table_lock);
    pgd = pgd_offset(current->mm, vaddr);
    printk("pdg_val = 0x%lx\n", pgd_val(*pgd));
    //printk("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }

    pud = pud_offset(pgd, vaddr);
    //printk("pud_val = 0x%lx\n", pud_val(*pud));
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    printk("pmd_val = 0x%lx\n", pmd_val(*pmd));
    //printk("pmd_index = %lu\n", pmd_index(vaddr));
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return -1;
    }

    pte = pte_offset_map(pmd, vaddr);
    printk("pte_val1 = 0x%lx\n",pte_val(*pte));
    //printk("pte_index = %lu\n", pte_index(vaddr));
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return -1;
    }

   /* if (pte_val(*pte) != 0){
        if(pte_val(*pte) &~_PAGE_PRESENT){ 
            tmp = __pte((pte_val(*pte)|_PAGE_PRESENT));
            set_pte(pte, tmp);
            return pte_val(*pte);
            }
    }*/
    if (pte_present(*pte)) {
	tmp = pte_clear_flags(*pte, (_AT(pteval_t, 1) << 51));
	//pte_clear(current->mm, vaddr, pte);
	//set_pte(pte, tmp);
	*(pte)=tmp;
    }
    spin_unlock(&current->mm->page_table_lock);
    printk("pf new pte_val = 0x%lx\n",pte_val(*pte));
    return 0;
}

unsigned long page_frame[2] = {0x405, 0x406};
unsigned long page_frame2[2] = {0x402, 0x403};   //female

int is_in_sequence(unsigned long frame) {
    int i;
    for (i = 0; i < 2; ++i) {
    	if (frame == page_frame[i])
	    return i+1;
    }
    return 0;
}


/*hook*/ 
asmlinkage int captain_hook(char* play_here) { 
    /*do whatever here (print "HAHAHA", reverse their string, etc) 
        But for now we will just print to the dmesg log*/ 
    struct task_struct * task = current;
    int i;
    unsigned long tmp;
    //unsigned int level;
    //pte_t *pte;
    if (!strcmp(task->comm, "demo"))
    {
        if ( !strcmp(play_here,"begin")) {
        //printk(KERN_INFO "in process %lu: task name %s.\n",(unsigned long)task->pid, task->comm);
            printk(KERN_INFO "begin clear present!!!!\n");
            for (i=0; i<2; i++) {
		//tmp = *((unsigned long*)(page_frame[i] << 12));
                vaddr2paddr(page_frame[i] << 12);
		vaddr2paddr(page_frame2[i] << 12);
                //printk("pte_val2 = 0x%lx\n",tmp);
            
            }
	    //__flush_tlb();
        }

        if ( !strcmp(play_here,"end")) {
            printk(KERN_INFO "end set present!!!!\n");
            for (i=0; i<2; i++) {
		//tmp = *((unsigned long*)(page_frame[i] << 12));
                setpresent(page_frame[i] << 12);
		setpresent(page_frame2[i] << 12);
                //printk("pte_val2 = 0x%lx\n",tmp);
            
            }
	    //__flush_tlb();
        }
    }

    return custom_syscall(play_here); 
} 
/*Make page writeable*/ 
int make_rw(unsigned long address){ 
    unsigned int level; 
    pte_t *pte = lookup_address(address, &level); 
    if(pte->pte &~_PAGE_RW){ 
        pte->pte |=_PAGE_RW; 
    } 
    return 0; 
} 
/* Make the page write protected */ 
int make_ro(unsigned long address){ 
    unsigned int level; 
    pte_t *pte = lookup_address(address, &level); 
    pte->pte = pte->pte &~_PAGE_RW; 
    return 0; 
} 
static int __init entry_point(void){ 
    printk(KERN_INFO "Captain Hook loaded successfully..\n"); 
    /*MY sys_call_table address*/ 
    system_call_table_addr = (void*)0xffffffff81801460; 
    /* Replace custom syscall with the correct system call name (write,open,etc) to hook*/ 
    custom_syscall = system_call_table_addr[__NR_clearpte]; 
    /*Disable page protection*/ 
    make_rw((unsigned long)system_call_table_addr); 
    /*Change syscall to our syscall function*/ 
    system_call_table_addr[__NR_clearpte] = captain_hook; 
    return 0; 
} 
static int __exit exit_point(void){ 
        printk(KERN_INFO "Unloaded Captain Hook successfully\n"); 
    /*Restore original system call */ 
    system_call_table_addr[__NR_clearpte] = custom_syscall; 
    /*Renable page protection*/ 
    make_ro((unsigned long)system_call_table_addr); 
    return 0; 
} 
module_init(entry_point); 
module_exit(exit_point); 
