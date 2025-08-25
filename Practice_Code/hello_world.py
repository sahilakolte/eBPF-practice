#!/usr/bin/env python3
# This tells the system to run the script using Python 3

from bcc import BPF         # Import BPF class from BCC to compile and load eBPF programs
from time import sleep      # Import sleep (not used here, but useful for future enhancements)

# Define the eBPF program in C syntax as a multi-line string
program = """
int hello_world(void *ctx) {
    // Print "Hello World!" to /sys/kernel/debug/tracing/trace_pipe
    bpf_trace_printk("Hello World!\\n");
    return 0; // Indicate successful execution
}
"""

# Compile and load the eBPF program into the kernel
b = BPF(text=program)

# Get the architecture-specific name of the 'clone' syscall (e.g., __x64_sys_clone)
clone = b.get_syscall_fnname("clone")

# Attach a kprobe to the 'clone' syscall, so that the eBPF program is triggered
# every time a new thread or process is created
b.attach_kprobe(event=clone, fn_name="hello_world")

# Continuously read and print trace output from /sys/kernel/debug/tracing/trace_pipe
# This shows "Hello World!" each time the clone syscall is invoked
b.trace_print()
