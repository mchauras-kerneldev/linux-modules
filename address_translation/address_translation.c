#include <asm-generic/errno-base.h>
#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>

#define NR_DEV 1

struct at_dev {
  struct cdev c_dev;
};

static dev_t first;       // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl;  // Global variable for the device class
/* static struct at_dev *at_devices; */

static void print_address(void *addr, char *name) {
  phys_addr_t phys_addr;
  phys_addr = virt_to_phys(addr);
  pr_info("************* Symbol %s *************\n", name);
  pr_info("Physical Address: 0x%llx\n", (unsigned long long)phys_addr);
  pr_info("Virtual Address: 0x%llx\n", (unsigned long long)addr);
}

int at_open(struct inode *inode, struct file *filp) {
  pr_info("Device Open\n");
  return 0; /* success */
}

int at_release(struct inode *inode, struct file *filp) {
  pr_info("Device Close\n");
  return 0;
}

/*
 * Idle page tracking only considers user memory pages, for other types of
 * pages the idle flag is always unset and an attempt to set it is silently
 * ignored.
 *
 * We treat a page as a user memory page if it is on an LRU list, because it is
 * always safe to pass such a page to rmap_walk(), which is essential for idle
 * page tracking. With such an indicator of user pages we can skip isolated
 * pages, but since there are not usually many of them, it will hardly affect
 * the overall result.
 *
 * This function tries to get a user memory page by pfn as described above.
 */
static struct folio *get_folio(unsigned long pfn) {
  struct page *page = pfn_to_page(pfn);
  struct folio *folio;
  pr_info("page: %p\n", page);
	usnigned long phys_mem = page_to_phys(page);

  if (!page || PageTail(page))
    return NULL;
  pr_info("Got Page\n");
  folio = page_folio(page);
  if (!folio_test_lru(folio) || !folio_try_get(folio))
    return NULL;
  pr_info("Got Folio\n");
  if (unlikely(page_folio(page) != folio || !folio_test_lru(folio))) {
    folio_put(folio);
    folio = NULL;
  }
  return folio;
}

void analyse_physical_address(const unsigned long addr) {
  struct folio *folio = get_folio(PHYS_PFN(addr));
  if (folio == NULL) {
    pr_err("Invalid Physical address: %lu\n", addr);
    return;
  }
  pr_info("Folio Address: %p\n", folio);
}

ssize_t at_write(struct file *filp, const char __user *buf, size_t count,
                 loff_t *f_pos) {
  char *data = (char *)kmalloc(4096, GFP_KERNEL);
  unsigned long addr;
  char c;
  memset(data, 0, 4096);
  if (copy_from_user(data, buf, count))
    return -EFAULT;
  if (kstrtoul(data + 1, 16, &addr)) {
    pr_warn("invalid address '%s'\n", data);
    return -EFAULT;
  }
  pr_info("Device Wrote %lu bytes: 0x%lX", count, addr);
  c = data[0];
  if (c == 'v') {
    print_address((void *)addr, "virtual to physical");
  } else {
    analyse_physical_address(addr);
  }

  return count;
}

struct file_operations at_fops = {
    .owner = THIS_MODULE,
    .write = at_write,
    .open = at_open,
    .release = at_release,
};

static void __exit address_translation_exit(void) {
  cdev_del(&c_dev);
  device_destroy(cl, first);
  class_destroy(cl);
  unregister_chrdev_region(first, 1);
  pr_info("Address Translation Module Unloaded\n");
}

static int __init address_translation_init(void) {
  pr_info("Address Translation Module Loaded\n");

  if (alloc_chrdev_region(&first, 0, NR_DEV, "at_dev") < 0) {
    return -1;
  }
  if ((cl = class_create("at_dev")) == NULL) {
    unregister_chrdev_region(first, 1);
    return -1;
  }
  if (device_create(cl, NULL, first, NULL, "at") == NULL) {
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
  cdev_init(&c_dev, &at_fops);
  if (cdev_add(&c_dev, first, 1) == -1) {
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }

  print_address((void *)&address_translation_init, "init");
  print_address((void *)&address_translation_exit, "exit");
  return 0;
}

module_init(address_translation_init);
module_exit(address_translation_exit);

MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION("Address Translation Module");
MODULE_LICENSE("GPL");
