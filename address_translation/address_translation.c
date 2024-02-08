#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <asm/io.h>

static int __init address_translation_init(void) {
  phys_addr_t phys_addr;
  pr_info("Address Translation Module Loaded\n");
  phys_addr = virt_to_phys((void *)&address_translation_init);
  pr_info("Physical Address: 0x%llx\n", (unsigned long long) phys_addr);
  pr_info("Virtual Address: 0x%llx\n", &address_translation_init);
  return 0;
}

static void __exit address_translation_exit(void) {
  pr_info("Address Translation Module Unloaded\n");
}

module_init(address_translation_init);
module_exit(address_translation_exit);

MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION("Address Translation Module");
MODULE_LICENSE("GPL");
