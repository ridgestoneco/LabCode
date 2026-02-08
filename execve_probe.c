#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARG_LEN 256
#define TASK_COMM_LEN 16

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char filename[MAX_ARG_LEN];
};

BPF_PERF_OUTPUT(events);

static __always_inline int is_suspicious_parent(char *comm) {
    if (comm[0]=='c' && comm[1]=='u' && comm[2]=='r' && comm[3]=='l' && comm[4]=='\0') return 1;
    if (comm[0]=='w' && comm[1]=='g' && comm[2]=='e' && comm[3]=='t' && comm[4]=='\0') return 1;
    if (comm[0]=='p' && comm[1]=='y' && comm[2]=='t' && comm[3]=='h' && comm[4]=='o' && comm[5]=='n' && comm[6]=='3') return 1;
    if (comm[0]=='p' && comm[1]=='y' && comm[2]=='t' && comm[3]=='h' && comm[4]=='o' && comm[5]=='n' && comm[6]=='\0') return 1;
    if (comm[0]=='p' && comm[1]=='e' && comm[2]=='r' && comm[3]=='l' && comm[4]=='\0') return 1;
    if (comm[0]=='p' && comm[1]=='h' && comm[2]=='p' && comm[3]=='\0') return 1;
    if (comm[0]=='r' && comm[1]=='u' && comm[2]=='b' && comm[3]=='y' && comm[4]=='\0') return 1;
    if (comm[0]=='n' && comm[1]=='o' && comm[2]=='d' && comm[3]=='e' && comm[4]=='\0') return 1;
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();

    bpf_probe_read_kernel_str(&event.pcomm, sizeof(event.pcomm),
                              &task->real_parent->comm);

    if (!is_suspicious_parent(event.pcomm))
        return 0;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid),
                          &task->real_parent->tgid);

    bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
                            (void *)args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
