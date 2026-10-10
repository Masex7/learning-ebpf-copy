#!/usr/bin/env python3
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int hello_execve(void* ctx) 
{
   u64 pid;
   u64 counter = 0;
   u64* p;
   
   bpf_trace_printk("Hello from hello_execve (execve syscall)");

   pid = bpf_get_current_pid_tgid() >> 32;
   p = counter_table.lookup(&pid);
   if (p != 0) 
   {
      counter = *p;
   }
   counter++;
   counter_table.update(&pid, &counter);
   return 0;
}

int hello_openat(void* ctx) 
{
   u64 pid;
   u64 counter = 0;
   u64* p;
   
   bpf_trace_printk("Hello from hello_openat (openat syscall)");

   pid = bpf_get_current_pid_tgid() >> 32;
   p = counter_table.lookup(&pid);
   if (p != 0) 
   {
      counter = *p;
   }
   counter++;
   counter_table.update(&pid, &counter);
   return 0;
}

int hello_write(void* ctx) 
{
   u64 pid;
   u64 counter = 0;
   u64* p;
   
   bpf_trace_printk("Hello from hello_write (write syscall)");

   pid = bpf_get_current_pid_tgid() >> 32;
   p = counter_table.lookup(&pid);
   if (p != 0) 
   {
      counter = *p;
   }
   counter++;
   counter_table.update(&pid, &counter);
   return 0;
}

int hello_connect(void* ctx) 
{
   u64 pid;
   u64 counter = 0;
   u64* p;
   
   bpf_trace_printk("Hello from hello_connect (connect syscall)");

   pid = bpf_get_current_pid_tgid() >> 32;
   p = counter_table.lookup(&pid);
   if (p != 0) 
   {
      counter = *p;
   }
   counter++;
   counter_table.update(&pid, &counter);
   return 0;
}

int hello_general(void* ctx) 
{
   u64 pid;
   u64 counter = 0;
   u64* p;
   
   bpf_trace_printk("Hello from hello_general (any syscall)");

   pid = bpf_get_current_pid_tgid() >> 32;
   p = counter_table.lookup(&pid);
   if (p != 0) 
   {
      counter = *p;
   }
   counter++;
   counter_table.update(&pid, &counter);
   return 0;
}
"""

b = BPF(text=program)
syscall1 = b.get_syscall_fnname("execve")
# syscall2 = b.get_syscall_fnname("openat")
# syscall3 = b.get_syscall_fnname("write")
syscall4 = b.get_syscall_fnname("connect")
b.attach_kprobe(event = syscall1, fn_name = "hello_execve")
# b.attach_kprobe(event = syscall2, fn_name = "hello_openat")
# b.attach_kprobe(event = syscall3, fn_name = "hello_write")
b.attach_kprobe(event = syscall4, fn_name = "hello_connect")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp = "sys_enter", fn_name = "hello_general")

while True:
    sleep(2)

    print(
        " ".join(
            f"PID {k.value}: {v.value}"
            for k, v in b["counter_table"].items()
        ),
        flush = True,
    )

    # while True:
    #     try:
    #         event = b.trace_fields(nonblocking = True)
    #     except ValueError:
    #         continue
    #
    #     if not event or not any(field is not None for field in event):
    #         break
    #
    #     task, pid, cpu, flags, timestamp, message = event
    #     if not message:
    #         break
    #
    #     task = (
    #         task.decode("utf-8", errors = "replace")
    #         if isinstance(task, bytes)
    #         else str(task or "<unknown>")
    #     )
    #     message = message.decode("utf-8", errors = "replace") if isinstance(message, bytes) else str(message)
    #     pid = str(pid) if pid is not None else "?"
    #
    #     print(
    #         f"{task:<16} PID {pid:<6} {message}",
    #         flush = True,
    #     )
