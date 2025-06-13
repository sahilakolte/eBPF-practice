#!/usr/bin/env python3
from bcc import BPF
from time import sleep

# This outputs a count of how many times the clone and execve syscalls have been made
# showing the use of an eBPF map (called syscall)
# Similar code as maps_v1 but without using hardcoded kprobe attachment

program = """
    BPF_HASH(syscall);

    int test_clone(void *ctx) {
        u64 counter = 0;
        u64 key = 56;
        u64 *p;

        p = syscall.lookup(&key);

        // The verifier will reject access to a pointer if you don't check that it's non-null first
        // Try commenting out the if test (and its closing brace) if you want to see the verifier do its thing
        if (p != 0) {
            counter = *p;
        }

        counter++;
        syscall.update(&key, &counter);

        return 0;
    }

    int test_execve(void *ctx) {
        u64 counter = 0;
        u64 key = 59;
        u64 *p;

        p = syscall.lookup(&key);
        if (p != 0) {
            counter = *p;
        }

        counter++;
        syscall.update(&key, &counter);

        return 0;
    }
"""

b = BPF(text=program)
clone = b.get_syscall_fnname("clone")
execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=clone, fn_name="test_clone")
b.attach_kprobe(event=execve, fn_name="test_execve")
while True:
    sleep(2)
    line = ""
    for k, v in b["syscall"].items():
        line += "syscall {0}: {1}\t".format(k.value, v.value)
    print(line)