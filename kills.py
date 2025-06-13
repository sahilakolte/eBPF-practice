#!/usr/bin/env python3

from bcc import BPF
from time import sleep

program = """
    #include <uapi/linux/ptrace.h>

    struct comm_t {
        char comm[30];
    };

    BPF_HASH(kills, u32, struct comm_t);

    int kprobe__sys_kill(struct pt_regs *ctx) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct comm_t data = {};
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        kills.update(&pid, &data);
        return 0;
    }
"""

b = BPF(text=program)

while True:
    sleep(2)
    for k, v in b["kills"].items():
        print("pid: {}\tname: {}".format(k.value, v.comm.decode()))
    b["kills"].clear()
    print("-"*30)