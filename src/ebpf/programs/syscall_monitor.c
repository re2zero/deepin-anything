// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/ebpf_common.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Helper function to send event to userspace with real path
static __always_inline void send_syscall_event(__u8 action, const char* pathname, __u32 flags) {
    struct vfs_event *event;
    
    // Only monitor file creation operations (when O_CREAT flag is set)
    if (action == ACT_NEW_FILE && !(flags & 0x40)) { // O_CREAT = 0x40
        return;
    }
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event manually
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = SYSCALL_SOURCE; // SYSCALL_SOURCE = 0
    
    // Get process information
    get_process_info(event);
    
    // Extract the real file path from syscall argument
    if (pathname) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), pathname);
    } else {
        bpf_probe_read_str(event->path, sizeof(event->path), "<unknown_path>");
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// System call monitoring with real path extraction
// These kprobes extract actual file paths from syscall arguments

SEC("kprobe/do_sys_openat2")
int trace_sys_openat2(struct pt_regs *ctx) {
    // Arguments: int dfd, const char __user *filename, struct open_how *how
    const char __user *filename = (const char __user *)PT_REGS_PARM2(ctx);
    
    // For simplicity, we'll treat all openat2 calls as potential file creation
    // In a real implementation, we'd need to check the flags in 'how' parameter
    send_syscall_event(ACT_NEW_FILE, filename, 0x40); // Assume O_CREAT for now
    return 0;
}

SEC("kprobe/do_sys_open")
int trace_sys_open(struct pt_regs *ctx) {
    // Arguments: const char __user *filename, int flags, umode_t mode
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    int flags = (int)PT_REGS_PARM2(ctx);
    
    send_syscall_event(ACT_NEW_FILE, filename, flags);
    return 0;
}

SEC("kprobe/do_unlinkat")
int trace_sys_unlinkat(struct pt_regs *ctx) {
    // Arguments: int dfd, const char __user *pathname, int flag
    const char __user *pathname = (const char __user *)PT_REGS_PARM2(ctx);
    
    send_syscall_event(ACT_DEL_FILE, pathname, 0);
    return 0;
}

SEC("kprobe/do_renameat2")
int trace_sys_renameat2(struct pt_regs *ctx) {
    // Arguments: int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags
    const char __user *oldname = (const char __user *)PT_REGS_PARM2(ctx);
    
    send_syscall_event(ACT_RENAME_FROM, oldname, 0);
    return 0;
}

// Note: This program focuses on syscall-level monitoring with real path extraction
// It complements the VFS layer monitoring but serves different purposes:
// - VFS layer: Fast, catches all VFS operations regardless of syscall path
// - Syscall layer: Slower, but provides real file paths and flags 