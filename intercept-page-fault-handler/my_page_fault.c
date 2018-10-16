#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/desc_defs.h>

//pt_regs
//#include <asm/ptrace.h>
//#include <asm/compat.h>
//vir2phy
#include <asm/page.h>

#include <linux/sched.h>
#include <linux/moduleparam.h>

//PGFAULT_NR is the interrupt number of page fault. It is platform specific.
#if defined(CONFIG_X86_64)
#define PGFAULT_NR X86_TRAP_PF
#else
#error This module is only for X86_64 kernel
#endif

static unsigned long new_idt_table_page;
static struct desc_ptr default_idtr;

//addresses of some symbols
static unsigned long addr_dft_page_fault = 0UL; //address of default 'page_fault'
static unsigned long addr_dft_do_page_fault = 0UL; //address of default 'do_page_fault'
static unsigned long addr_pv_irq_ops = 0UL; //address of 'pv_irq_ops'
static unsigned long addr_adjust_exception_frame; //content of pv_irq_ops.adjust_exception_frame, it's a function
static unsigned long addr_error_entry = 0UL;
static unsigned long addr_error_exit = 0UL;

/*
struct pt_regs {
    long    ebx;
    long    ecx;
    long    edx;
    long    esi;
    long    edi;
    long    ebp;
    long    eax;
    int     xds;
    int     xes;
    long    orig_eax;
    long    eip;
    int     xcs;
    long    eflags;
    long    esp;
    int     xss;
};
*/

module_param(addr_dft_page_fault, ulong, S_IRUGO);
module_param(addr_dft_do_page_fault, ulong, S_IRUGO);
module_param(addr_pv_irq_ops, ulong, S_IRUGO);
module_param(addr_error_entry, ulong, S_IRUGO);
module_param(addr_error_exit, ulong, S_IRUGO);

#define CHECK_PARAM(x) do{\
    if(!x){\
        printk(KERN_INFO "my_virt_drv: Error: need to set '%s'\n", #x);\
        is_any_unset = 1;\
    }\
    printk(KERN_INFO "my_virt_drv: %s=0x%lx\n", #x, x);\
}while(0)



static int check_parameters(void){
    int is_any_unset = 0;
    CHECK_PARAM(addr_dft_page_fault);
    CHECK_PARAM(addr_dft_do_page_fault);
    CHECK_PARAM(addr_pv_irq_ops);
    CHECK_PARAM(addr_error_entry);
    CHECK_PARAM(addr_error_exit);
    return is_any_unset;
}

typedef void (*do_page_fault_t)(struct pt_regs*, unsigned long);

static void get_pgtable_macro(void) {
    printk("PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
    printk("PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
    printk("PUD_SHIFT = %d\n", PUD_SHIFT);
    printk("PMD_SHIFT = %d\n", PMD_SHIFT);
    printk("PAGE_SHIFT = %d\n", PAGE_SHIFT);

    printk("PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
    printk("PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
    printk("PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
    printk("PTRS_PER_PTE = %d\n", PTRS_PER_PTE);
   
    printk("sizeof pte_t = %d\n", sizeof(pte_t));
    printk("PAGE_MASK = 0x%lx\n", PAGE_MASK);
}


static unsigned long clear_present(unsigned long vaddr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t tmp;
    spin_lock(&current->mm->page_table_lock);
    pgd = pgd_offset(current->mm,vaddr);
    //printk("pf pdg_val = 0x%lx\n", pgd_val(*pgd));
    //printk("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return 0;
    }

    pud = pud_offset(pgd, vaddr);
    //printk("pf pud_val = 0x%lx\n", pud_val(*pud));
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return 0;
    }

    pmd = pmd_offset(pud, vaddr);
    //printk("pf pmd_val = 0x%lx\n", pmd_val(*pmd));
    //printk("pmd_index = %lu\n", pmd_index(vaddr));
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return 0;
    }

    pte = pte_offset_map(pmd, vaddr);
    printk("pf old pte_val = 0x%lx\n",pte_val(*pte));
    //printk("pte_index = %lu\n", pte_index(vaddr));
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return 0;
    }
/*
    if (pte_val(*pte) != 0){
        tmp = __pte((pte_val(*pte)&~_PAGE_PRESENT));
        set_pte(pte, tmp); 
        return pte_val(*pte);
    }
*/
    if (pte_present(*pte)){
	tmp = pte_set_flags(*pte, (_AT(pteval_t, 1) << 51));
	//pte_clear(current->mm, vaddr, pte);    	
	//set_pte(pte, tmp);
	*(pte)=tmp;
	//__flush_tlb();
    }
    spin_unlock(&current->mm->page_table_lock);
    printk("pf new pte_val = 0x%lx\n",pte_val(*pte));
    return 1;
}






static unsigned long vaddr2paddr(unsigned long vaddr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t tmp;
 
    spin_lock(&current->mm->page_table_lock);
    pgd = pgd_offset(current->mm, vaddr);
    //printk("pf pdg_val = 0x%lx\n", pgd_val(*pgd));
    //printk("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return 0;
    }

    pud = pud_offset(pgd, vaddr);
    //printk("pf pud_val = 0x%lx\n", pud_val(*pud));
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return 0;
    }

    pmd = pmd_offset(pud, vaddr);
    //printk("pf pmd_val = 0x%lx\n", pmd_val(*pmd));
    //printk("pmd_index = %lu\n", pmd_index(vaddr));
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return 0;
    }

    pte = pte_offset_map(pmd, vaddr);
    printk("pf old pte_val = 0x%lx\n",pte_val(*pte));
    //printk("pte_index = %lu\n", pte_index(vaddr));
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return 0;
    }
/*
    if (pte_val(*pte) != 0){
        if(pte_val(*pte) &~_PAGE_PRESENT){ 
            tmp = __pte((pte_val(*pte)|_PAGE_PRESENT));
            set_pte(pte, tmp);
            return pte_val(*pte);
            }
    }
*/
    if(pte_present(*pte)){
	tmp = pte_clear_flags(*pte, (_AT(pteval_t, 1) << 51));
	//pte_clear(current->mm, vaddr, pte);
	//set_pte(pte, tmp);
	*(pte)=tmp;
	//__flush_tlb();
    }
    spin_unlock(&current->mm->page_table_lock);
    printk("pf new pte_val = 0x%lx\n",pte_val(*pte));
    return 1;
}

unsigned long page_frame[2] = {0x405, 0x406};   //male
unsigned long page_frame2[2] = {0x402, 0x403};   //female
bool g_con = false;
bool g_con2 = false;

int is_in_sequence(unsigned long frame) {
    int i;
    for (i = 0; i < 2; ++i) {
    	if (frame == page_frame[i])
	    return i+1;
    }
    return 0;
}

int is_in_sequence2(unsigned long frame) {
    int i;
    for (i = 0; i < 2; ++i) {
    	if (frame == page_frame2[i])
	    return i+1;
    }
    return 0;
}

void my_do_page_fault(struct pt_regs* regs, unsigned long error_code){
    struct task_struct * task = current;
    //struct mm_struct * curmm = current->mm;
    //pgd_t * pgd;
    //pmd_t * pmd;
    //pud_t * pud;
    //pte_t * pte;
    //unsigned long pa;
    unsigned long address;
    unsigned long tmp;
    unsigned long tmp_p;
    int index;
    int index2;

    //printk(KERN_INFO "in process %lu: pte %lx.\n", (unsigned long)task->pid,pa);
    
    
    if (!strcmp(task->comm, "demo"))
    {
        //printk(KERN_INFO "in process %lu: task name %s.\n",(unsigned long)task->pid, task->comm);
        address = read_cr2();
        printk(KERN_INFO "in process %lu: Page fault address %lx.\n",(unsigned long)task->pid, address);
        printk(KERN_INFO "in process %lu: page base address %lx.\n",(unsigned long)task->pid, (address >> 12));
        if(g_con) {
	    g_con = false;
	    clear_present(page_frame[0] << 12);
	}
	if(g_con2) {
	    g_con2 = false;
	    clear_present(page_frame2[0] << 12);
	}
        index = is_in_sequence(address>>12);
        if(index) {
            //printk(KERN_INFO "in process %lu: EIP %lx.\n",(unsigned long)task->pid, regs->ip);
	    printk(KERN_INFO "index: %d\n", index -1 );
            if(!vaddr2paddr(address))
		goto target;
  	    __flush_tlb();
	    if (index != 1) {//index =2 no.2
	        vaddr2paddr(page_frame[0] << 12);
 		g_con = true;
  	    }
	    else
		clear_present(page_frame[1] << 12);  //index=1
	    __flush_tlb();
	    return;
        }
        index2 = is_in_sequence2(address>>12);
        if(index2) {
            //printk(KERN_INFO "in process %lu: EIP %lx.\n",(unsigned long)task->pid, regs->ip);
	    printk(KERN_INFO "index2: %d\n", index2 -1 );
            if(!vaddr2paddr(address))
		goto target;
  	    __flush_tlb();
	    if (index2 != 1) {
	        vaddr2paddr(page_frame2[0] << 12);
 		g_con2 = true;
  	    }
	    else
		clear_present(page_frame2[1] << 12);
	    __flush_tlb();
	    return;
        }
	//return;
    }
target:
    ((do_page_fault_t)addr_dft_do_page_fault)(regs, error_code);
}

asmlinkage void my_page_fault(void);
asm("   .text");
asm("   .type my_page_fault,@function");
asm("my_page_fault:");
asm("   .byte 0x66");
asm("   xchg %ax, %ax");
asm("   callq *addr_adjust_exception_frame");
asm("   sub $0x78, %rsp");
asm("   callq *addr_error_entry");
asm("   mov %rsp, %rdi");
asm("   mov 0x78(%rsp), %rsi");
asm("   movq $0xffffffffffffffff, 0x78(%rsp)");
asm("   callq my_do_page_fault");
asm("   jmpq *addr_error_exit");
asm("   nopl (%rax)");

//this function is copied from kernel source
static inline void pack_gate(gate_desc *gate, unsigned type, unsigned long func,
                         unsigned dpl, unsigned ist, unsigned seg){
    gate->offset_low    = PTR_LOW(func);
    gate->segment       = __KERNEL_CS;
    gate->ist       = ist;
    gate->p         = 1;
    gate->dpl       = dpl;
    gate->zero0     = 0;
    gate->zero1     = 0;
    gate->type      = type;
    gate->offset_middle = PTR_MIDDLE(func);
    gate->offset_high   = PTR_HIGH(func);
}

static void my_load_idt(void *info){
    struct desc_ptr *idtr_ptr = (struct desc_ptr *)info;
    load_idt(idtr_ptr);
}

static int my_fault_init(void){
    //check all the module_parameters are set properly
    if(check_parameters())
        return -1;
    //get the address of 'adjust_exception_frame' from pv_irq_ops struct
    addr_adjust_exception_frame = *(unsigned long *)(addr_pv_irq_ops + 0x30);
    return 0;
}

int register_my_page_fault_handler(void){
    struct desc_ptr idtr;
    gate_desc *old_idt, *new_idt;
    int retval;

    //first, do some initialization work.
    retval = my_fault_init();
    if(retval)
        return retval;

    //record the default idtr
    store_idt(&default_idtr);

    //read the content of idtr register and get the address of old IDT table
    old_idt = (gate_desc *)default_idtr.address; //'default_idtr' is initialized in 'my_virt_drv_init'
    printk(KERN_INFO "my_virt_drv: save old idt idt table.0x%lx\n",(long unsigned int)old_idt);
    //allocate a page to store the new IDT table
    printk(KERN_INFO "my_virt_drv: alloc a page to store new idt table.\n");
    new_idt_table_page = __get_free_page(GFP_KERNEL);
    if(!new_idt_table_page)
        return -ENOMEM;

    idtr.address = new_idt_table_page;
    idtr.size = default_idtr.size;
    
    //copy the old idt table to the new one
    new_idt = (gate_desc *)idtr.address;
    memcpy(new_idt, old_idt, idtr.size);
    pack_gate(&new_idt[PGFAULT_NR], GATE_INTERRUPT, (unsigned long)my_page_fault, 0, 0, __KERNEL_CS);
    //get_pgtable_macro();
    //load idt for all the processors
    printk(KERN_INFO "my_virt_drv: load the new idt table.0x%lx\n",(long unsigned int)new_idt);
    printk(KERN_INFO "my_virt_drv: my_page_fault.0x%lx\n",(unsigned long)my_page_fault);
    printk(KERN_INFO "my_virt_drv: addr_dft_do_page_fault.0x%lx\n",(unsigned long)addr_dft_do_page_fault);
    //printk(KERN_INFO "my_virt_drv: clear_present.0x%lx\n",(unsigned long)clear_present);
    //printk(KERN_INFO "my_virt_drv: vaddr2paddr.0x%lx\n",(unsigned long)vaddr2paddr);
    load_idt(&idtr);
    printk(KERN_INFO "my_virt_drv: new idt table loaded.\n");
    smp_call_function(my_load_idt, (void *)&idtr, 1); //wait till all are finished
    printk(KERN_INFO "my_virt_drv: all CPUs have loaded the new idt table.\n");
    return 0;
}

void unregister_my_page_fault_handler(void){
    struct desc_ptr idtr;
    store_idt(&idtr);
    //if the current idt is not the default one, restore the default one
    if(idtr.address != default_idtr.address || idtr.size != default_idtr.size){
        load_idt(&default_idtr);
        smp_call_function(my_load_idt, (void *)&default_idtr, 1);
        free_page(new_idt_table_page);
    }
}

MODULE_LICENSE("Dual BSD/GPL");
