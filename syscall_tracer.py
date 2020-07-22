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
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>

BPF_HASH(data, u32, u64);

int trace_syscall_entry(struct pt_regs *ctx)
{
     if (!PT_REGS_PARM1(ctx))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    struct pid_namespace *pidns = (struct pid_namespace *)task->nsproxy->pid_ns_for_children;
    if (pidns->level == 0) {
        return 0;
    }
    // bpf_trace_printk("pidns->level = %d", pidns->level);

    u32 key = ctx->ax;
    u64 zero = 0;
    u64 *val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        ++(*val);
    }

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
    syscalls_map =  {str(syscall_name(k.value).decode()): v.value for k, v in b["data"].items()}
    # data["pid"] = args.pid
    # data["command"] = get_command(args.pid)
    data["syscalls"] = syscalls_map
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
