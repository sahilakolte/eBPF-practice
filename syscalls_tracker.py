#!/usr/bin/python3

from bcc import BPF
from bcc.syscall import syscall_name
from time import sleep

program = r"""
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
    BPF_HASH(syscall_counter);

    int counter(struct tracepoint__raw_syscalls__sys_enter *ctx) {
        u64 id = ctx->id;
        u64 count = 0;
        u64 *p;

        p = syscall_counter.lookup(&id);
        if (p != 0) {
            count = *p;
        }

        count++;
        syscall_counter.update(&id, &count);

        return 0;
    }
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="counter")

print("Tracing syscalls:")

try:
    while True:
        sleep(2)
        with open("syscalls.log", "w") as f:
            for k, v in b["syscall_counter"].items():
                sys_name = syscall_name(k.value)
                name = sys_name.decode()
                f.write(f"{name:20s} : {v.value}\n")
except KeyboardInterrupt:
    print("\n---End---")
