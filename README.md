# 🛡️ ExecWatch Kernel Module

A small Linux kernel module that hooks the kernel exec path (via a kprobe) to record process execution events and exposes the recent events via `/proc/execwatch`.
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
