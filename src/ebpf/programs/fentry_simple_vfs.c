// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/ebpf_common.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} fentry_simple_events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Simplified event sender (without complex path extraction for now)
static __always_inline void send_fentry_simple_event(__u8 action, const char* operation_name) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&fentry_simple_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = VFS_SOURCE;
    
    // Get process information
    get_process_info(event);
    
    // Set operation name
    if (operation_name) {
        bpf_probe_read_str(event->path, sizeof(event->path), operation_name);
    } else {
        bpf_probe_read_str(event->path, sizeof(event->path), "<fentry_vfs>");
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// Simplified fentry hooks to test the concept
// These will show better performance characteristics than kprobes

SEC("fentry/vfs_create")
int BPF_PROG(fentry_vfs_create) {
    send_fentry_simple_event(ACT_NEW_FILE, "fentry_create");
    return 0;
}

SEC("fentry/vfs_mkdir") 
int BPF_PROG(fentry_vfs_mkdir) {
    send_fentry_simple_event(ACT_NEW_FOLDER, "fentry_mkdir");
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink) {
    send_fentry_simple_event(ACT_DEL_FILE, "fentry_unlink");
    return 0;
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(fentry_vfs_rmdir) {
    send_fentry_simple_event(ACT_DEL_FOLDER, "fentry_rmdir");
    return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename) {
    send_fentry_simple_event(ACT_RENAME_FROM, "fentry_rename");
    return 0;
}

// Test the performance difference between fentry and kprobe
// This will allow us to verify if fentry is indeed faster 