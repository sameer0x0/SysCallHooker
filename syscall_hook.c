#include <linux/module.h>   
#include <linux/kernel.h>    
#include <linux/init.h>      
#include <linux/fs.h>        
#include <linux/uaccess.h>   
#include <linux/syscalls.h>  
#include <asm/unistd.h>     

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Sameer Roy");
MODULE_DESCRIPTION("A simple system call hooking for security imporvement");

static asmlinkage long (*original_open)(const char __user *, int, umode_t); 


asmlinkage long hooked_open(const char __user *filename, int flags, umode_t mode) {

    printk(KERN_INFO "Hooked open() called for file: %s\n", filename);  
    return original_open(filename, flags, mode);

}

static unsigned long **find_sys_call_table(void) {

    unsigned long **sys_call_table = (unsigned long **)0xFFFFFFFF81000000;  

    while (!sys_call_table[__NR_close]) {
        sys_call_table++;
    }

    return sys_call_table;
}

static int __init syscall_hook_init(void) {
    
    unsigned long **sys_call_table;

    sys_call_table = find_sys_call_table();
    
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to locate the system call table\n");
        return -1;      
    }

    original_open = (void *)sys_call_table[__NR_open];
    write_cr0(read_cr0() & (~0x10000));  
    sys_call_table[__NR_open] = (unsigned long *)hooked_open;
    write_cr0(read_cr0() | 0x10000);  

    printk(KERN_INFO "Successfully hooked the open() system call!\n");
    
    return 0;  
}

static void __exit syscall_hook_exit(void) {
    unsigned long **sys_call_table;

    sys_call_table = find_sys_call_table();
    if (!sys_call_table) {

        printk(KERN_ERR "Failed to locate the system call table during exit\n");

        return;
    }

    write_cr0(read_cr0() & (~0x10000));  
    sys_call_table[__NR_open] = (unsigned long *)original_open;  
    write_cr0(read_cr0() | 0x10000); 

    printk(KERN_INFO "Restored the original open() system call\n");
}

module_init(syscall_hook_init);
module_exit(syscall_hook_exit);
