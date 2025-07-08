#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#if defined(__powerpc__)
#include <asm/time.h>
#define read_tb() mftb()
#define tb_to_ns_wrapper(tb) tb_to_ns(tb)
#else
#include <linux/ktime.h>
#define read_tb() ktime_get_ns()  // fallback for x86
#define tb_to_ns_wrapper(tb) (tb) // no conversion needed on x86 fallback
#warning                                                                       \
	"This module is designed for PowerPC. Using fallback timestamps on x86."
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION(
		"PowerPC Idle wakeup latency with debugfs output and averaging");
MODULE_VERSION("1.0");

#define BUF_LEN 16
#define NUM_SAMPLES 10
#define SLEEP_NS 10000000 // 10ms

static struct dentry *dir;
static struct task_struct *load_thread;
static struct task_struct *test_thread;
static char results_buf[1024];
static DEFINE_MUTEX(results_lock);

static int load_fn(void *data) {
	int cpu = (long)data;
	set_cpus_allowed_ptr(current, cpumask_of(cpu));
	pr_info("Load thread running on CPU %d\n", cpu);
	while (!kthread_should_stop())
		cpu_relax();
	pr_info("Load thread stopped on CPU %d\n", cpu);
	return 0;
}

static int test_fn(void *data) {
	int cpu = (long)data;
	uint64_t tb_before, tb_after, total = 0;
	uint64_t latencies[NUM_SAMPLES];
	ktime_t timeout = ns_to_ktime(SLEEP_NS);

	set_cpus_allowed_ptr(current, cpumask_of(cpu));
	sched_set_fifo(current);

	msleep(100); // allow idle

	pr_info("Test thread running on CPU %d\n", cpu);
	for (int i = 0; i < NUM_SAMPLES; i++) {
		tb_before = read_tb();
		schedule_hrtimeout_range(&timeout, HRTIMER_MODE_REL, CLOCK_MONOTONIC);
		tb_after = read_tb();
		latencies[i] = tb_after - tb_before;
		total += latencies[i];
		msleep(10);
	}

	mutex_lock(&results_lock);
	snprintf(
			results_buf, sizeof(results_buf),
			"[CPU %d] Latency over %d samples:\n  Avg: %llu TB ticks (%llu ns)\n",
			cpu, NUM_SAMPLES, total / NUM_SAMPLES,
			tb_to_ns_wrapper((total / NUM_SAMPLES)));
	mutex_unlock(&results_lock);

	pr_info("Test thread exiting from CPU %d\n", cpu);
	pr_info("%s", results_buf);
	test_thread = NULL;
	return 0;
}

static ssize_t write_load(struct file *file, const char __user *ubuf,
		size_t count, loff_t *ppos) {
	char buf[BUF_LEN] = {};
	int cpu;

	if (count >= BUF_LEN)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	if (kstrtoint(buf, 10, &cpu))
		return -EINVAL;
	if (!cpu_online(cpu)) {
		pr_err("CPU %d is not online\n", cpu);
		return -EINVAL;
	}
	if (load_thread)
		kthread_stop(load_thread);

	load_thread = kthread_run(load_fn, (void *)(long)cpu, "smt_load_cpu%d", cpu);
	if (IS_ERR(load_thread)) {
		pr_err("Failed to start load thread on CPU %d\n", cpu);
		load_thread = NULL;
		return PTR_ERR(load_thread);
	}

	return count;
}

static ssize_t write_test(struct file *file, const char __user *ubuf,
		size_t count, loff_t *ppos) {
	char buf[BUF_LEN] = {};
	int cpu;

	if (count >= BUF_LEN)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	if (kstrtoint(buf, 10, &cpu))
		return -EINVAL;
	if (!cpu_online(cpu)) {
		pr_err("CPU %d is not online\n", cpu);
		return -EINVAL;
	}
	if (test_thread) {
		kthread_stop(test_thread);
	}

	test_thread = kthread_run(test_fn, (void *)(long)cpu, "smt_test_cpu%d", cpu);
	if (IS_ERR(test_thread)) {
		pr_err("Failed to start test thread on CPU %d\n", cpu);
		test_thread = NULL;
		return PTR_ERR(test_thread);
	}

	return count;
}

static ssize_t read_results(struct file *file, char __user *ubuf, size_t count,
		loff_t *ppos) {
	ssize_t len;
	mutex_lock(&results_lock);
	len = simple_read_from_buffer(ubuf, count, ppos, results_buf,
			strlen(results_buf));
	mutex_unlock(&results_lock);
	return len;
}

static const struct file_operations fops_load = {
	.write = write_load,
};

static const struct file_operations fops_test = {
	.write = write_test,
};

static const struct file_operations fops_results = {
	.read = read_results,
};

static int __init idle_measurement_init(void) {
	dir = debugfs_create_dir("idle_measurement", NULL);
	if (!dir)
		return -ENOMEM;

	debugfs_create_file("load_cpu", 0200, dir, NULL, &fops_load);
	debugfs_create_file("test_cpu", 0200, dir, NULL, &fops_test);
	debugfs_create_file("results", 0400, dir, NULL, &fops_results);

	pr_info("Idle latency module loaded (debugfs: "
			"/sys/kernel/debug/idle_measurement)\n");
	return 0;
}

static void __exit idle_measurement_exit(void) {
	if (load_thread) {
		int ret = kthread_stop(load_thread);
		if (ret < 0)
			pr_warn("Failed to stop load_thread: %d\n", ret);
		load_thread = NULL;
	}

	if (test_thread) {
		int ret = kthread_stop(test_thread);
		if (ret < 0)
			pr_warn("Failed to stop test_thread: %d\n", ret);
		test_thread = NULL;
	}

	// Always clean up debugfs
	if (dir)
		debugfs_remove_recursive(dir);

	pr_info("Idle latency module unloaded\n");
}

module_init(idle_measurement_init);
module_exit(idle_measurement_exit);
