#!/usr/bin/env python3
from bcc import BPF
from bcc.utils import printb

program = """
    int kprobe__sys_sync(void *ctx) {
        // This function is called whenever the sync syscall is invoked
        // It prints a message to the trace pipe
        bpf_trace_printk("Sync was called!\\n");
        return 0;
    }
"""

b = BPF(text=program)

print("%-18s %-16s %-6s %s" % ("TIME", "COMM", "PID", "MSG"))

while 1:
    try:
        # Fixed : Use b.trace_fields() to get structured output
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))