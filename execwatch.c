#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timekeeping.h>

#define PROC_NAME "execwatch"
#define MAX_EVENTS 128
#define MAX_PATH_LEN 256

struct exec_event {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
    ktime_t ts;
};

static struct exec_event events[MAX_EVENTS];
static unsigned int write_idx;
static DEFINE_SPINLOCK(events_lock);

static struct kprobe kp = {
    .symbol_name = "do_execveat_common",
};

static void push_event(pid_t pid, const char *comm, const char *path)
{
    unsigned long flags;
    spin_lock_irqsave(&events_lock, flags);
    events[write_idx].pid = pid;
    strncpy(events[write_idx].comm, comm, TASK_COMM_LEN - 1);
    events[write_idx].comm[TASK_COMM_LEN - 1] = '\0';
    strncpy(events[write_idx].path, path, MAX_PATH_LEN - 1);
    events[write_idx].path[MAX_PATH_LEN - 1] = '\0';
    events[write_idx].ts = ktime_get_real();
    write_idx = (write_idx + 1) % MAX_EVENTS;
    spin_unlock_irqrestore(&events_lock, flags);
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char path[MAX_PATH_LEN];
    const char __user *u_path = (const char __user *)regs->di;
    int ret = strncpy_from_user(path, u_path, MAX_PATH_LEN - 1);
    if (ret <= 0)
        path[0] = '\0';
    else
        path[ret] = '\0';

    push_event(current->pid, current->comm, path);
    printk(KERN_INFO "execwatch: pid=%d comm=%s path=%s\n", current->pid, current->comm, path);
    return 0;
}

static int execwatch_show(struct seq_file *m, void *v)
{
    unsigned int i, idx;
    for (i = 0; i < MAX_EVENTS; i++) {
        idx = (write_idx + i) % MAX_EVENTS;
        if (events[idx].pid == 0)
            continue;
        seq_printf(m, "%llu: pid=%d comm=%s path=%s\n",
                   (unsigned long long)ktime_to_ns(events[idx].ts),
                   events[idx].pid,
                   events[idx].comm,
                   events[idx].path);
    }
    return 0;
}

static int execwatch_open(struct inode *inode, struct file *file)
{
    return single_open(file, execwatch_show, NULL);
}

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = execwatch_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init execwatch_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("execwatch: register_kprobe failed: %d\n", ret);
        return ret;
    }
    if (!proc_create(PROC_NAME, 0444, NULL, &proc_fops)) {
        unregister_kprobe(&kp);
        pr_err("execwatch: proc_create failed\n");
        return -ENOMEM;
    }
    pr_info("execwatch: module loaded, kprobe at %s\n", kp.symbol_name);
    return 0;
}

static void __exit execwatch_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    unregister_kprobe(&kp);
    pr_info("execwatch: module unloaded\n");
}

module_init(execwatch_init);
module_exit(execwatch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavithrnnnn");
MODULE_DESCRIPTION("ExecWatch");
