#!/usr/bin/python3
import argparse
import json
import time
from bcc import BPF
from bcc.syscall import syscall_name, syscalls

parser = argparse.ArgumentParser(description="syscall trace per process")
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_HASH(data, u32, u64);

int trace_syscall_entry(struct pt_regs *ctx)
{
     if (!PT_REGS_PARM1(ctx))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

#ifdef FILTER_PID
    if (pid_tgid >> 32 != FILTER_PID) {
        return 0;
    }
#endif

    u32 key = ctx->ax;
    u64 zero = 0;
    u64 *val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        ++(*val);
    }

    // bpf_trace_printk("CMD: %s PID: %d SYSCALL: %d \\n", comm, pid_tgid, ctx->ax);
    return 0;
}
"""

if args.pid:
    bpf_text  = "#define FILTER_PID {}\n".format(args.pid) + bpf_text
if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
b.attach_kprobe(event="do_syscall_64", fn_name="trace_syscall_entry")

def get_command(pid):
    data = ""
    with open("/proc/{}/cmdline".format(pid)) as f:
        data = f.read()

    return data.strip().strip("\u0000")

def json_dump():
    data = dict()
    d =  {str(syscall_name(k.value).decode()): v.value for k, v in b["data"].items()}
    data["pid"] = args.pid
    data["command"] = get_command(args.pid)
    data["syscalls"] = d
    return json.dumps(data)

def print_result():
    for k, v in b["data"].items():
        if k.value == 0xFFFFFFFF:
            continue
        print("{}: {}".format(syscall_name(k.value).decode(), v.value))


while True:
    try:
        time.sleep(1)
        print(json_dump())
    except KeyboardInterrupt:
        b["data"].clear()
        exit()

    except Exception as e:
        print(e)
        b["data"].clear()
        exit(1)
