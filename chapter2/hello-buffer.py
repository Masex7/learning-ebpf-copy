#!/usr/bin/env python3
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output); 

struct data_t 
{     
   int pid;
   int uid;
   char command[16];
   char message[20];
};

int hello(void *ctx) 
{
   struct data_t data = {};
   const char evenMessage[] = "Hello Even World!";
   const char oddMessage[] = "Hello Odd World!";
   const char* message;

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   if (data.pid % 2 == 0)
       message = evenMessage;
   else
       message = oddMessage;

   bpf_get_current_comm(data.command, sizeof(data.command));
   bpf_probe_read_kernel(data.message, sizeof(data.message), message);

   output.perf_submit(ctx, &data, sizeof(data)); 

   return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")


def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")


b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()