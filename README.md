# 🛡️ ExecWatch Kernel Module

A small Linux kernel module that hooks the kernel exec path (via a kprobe) to record process execution events and exposes the recent events via `/proc/execwatch`.
My First project on Linux Drivers 😅


## ✨ Why this is useful 

- 🖥️ Demonstrates kernel instrumentation (kprobes) and procfs exposure.
- 🔍 Useful for building auditing tools or understanding userland executions.
- 🚨 Can be extended to detect suspicious executions (setuid binaries, executions from writable directories, unexpected interpreters, etc..).


## 📂 Files

- `driver_no_comments.c` —  source code
- `Makefile` — build the module


## 🛠️ Building

```bash
# set KERNEL_SRC to your kernel build headers path if necessary
make
# produces execwatch.ko
````

## 🚀 Installing

```bash
sudo insmod execwatch.ko
# check dmesg for confirmation
cat /proc/execwatch
```

## 👀 Usage

* `cat /proc/execwatch` shows the most recent execution events (pid, comm, argv0/file, timestamp).
* `dmesg` will also log each event during module load.

---------------------------------------------------------------------------------------------

## ⚠️ Caution: Dos and Don'ts

##  ✅ Dos:

- Test inside a virtual machine (VirtualBox, QEMU, Multipass) first.

- Double-check kernel symbols (do_execveat_common) exist on your target kernel.

- Keep backups of important data; kernel crashes can corrupt files.

- Use root privileges only when necessary for insmod and reading /proc/execwatch.

## ❌ Don'ts:

- Don't run on a production system without proper testing.

- Don't modify kernel internals unless you understand the impact.

- Don't ignore dmesg warnings; they may indicate misbehavior.

- Don't assume this module provides security by itself; it's for monitoring and learning.


## 📜 License

MIT

