#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <asm/io.h>

static void print_address(void* addr, char* name) {
  phys_addr_t phys_addr;
  phys_addr = virt_to_phys(addr);
  pr_info("************* Symbol %s *************\n", name);
  pr_info("Physical Address: 0x%llx\n", (unsigned long long) phys_addr);
  pr_info("Virtual Address: 0x%llx\n", (unsigned long long) addr);
}

static void __exit address_translation_exit(void) {
  pr_info("Address Translation Module Unloaded\n");
}

static int __init address_translation_init(void) {
  pr_info("Address Translation Module Loaded\n");
  print_address((void *) &address_translation_init, "address_translation_init");
  print_address((void *) &address_translation_exit, "address_translation_exit");
  return 0;
}

module_init(address_translation_init);
module_exit(address_translation_exit);

MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION("Address Translation Module");
MODULE_LICENSE("GPL");
