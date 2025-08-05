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
} vfs_events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Helper function to send event to userspace
static __always_inline void send_vfs_event(__u8 action, const char* operation_name, __u32 source_type) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&vfs_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event manually (eBPF doesn't support memset)
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = source_type; // VFS_SOURCE = 1
    
    // Get process information
    get_process_info(event);
    
    // Use operation name to describe the VFS operation
    if (operation_name) {
        bpf_probe_read_str(event->path, sizeof(event->path), operation_name);
    } else {
        // Generate a descriptive path for VFS operations
        switch (action) {
            case ACT_NEW_FILE:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_create_file>");
                break;
            case ACT_NEW_FOLDER:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_create_dir>");
                break;
            case ACT_DEL_FILE:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_delete_file>");
                break;
            case ACT_DEL_FOLDER:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_delete_dir>");
                break;
            case ACT_RENAME_FROM:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_rename>");
                break;
            case ACT_NEW_LINK:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_link>");
                break;
            case ACT_NEW_SYMLINK:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_symlink>");
                break;
            default:
                bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_operation>");
                break;
        }
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// VFS kprobes for file system structure changes only
// These focus on actual file system structure modifications

SEC("kprobe/vfs_create")
int trace_vfs_create(struct pt_regs *ctx) {
    send_vfs_event(ACT_NEW_FILE, "<vfs_create>", VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_mkdir")
int trace_vfs_mkdir(struct pt_regs *ctx) {
    send_vfs_event(ACT_NEW_FOLDER, "<vfs_mkdir>", VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_unlink")
int trace_vfs_unlink(struct pt_regs *ctx) {
    send_vfs_event(ACT_DEL_FILE, "<vfs_unlink>", VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_rmdir")
int trace_vfs_rmdir(struct pt_regs *ctx) {
    send_vfs_event(ACT_DEL_FOLDER, "<vfs_rmdir>", VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
    send_vfs_event(ACT_RENAME_FROM, "<vfs_rename>", VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_link")
int trace_vfs_link(struct pt_regs *ctx) {
    send_vfs_event(ACT_NEW_LINK, "<vfs_link>", VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_symlink")
int trace_vfs_symlink(struct pt_regs *ctx) {
    send_vfs_event(ACT_NEW_SYMLINK, "<vfs_symlink>", VFS_SOURCE);
    return 0;
}

// Note: Removed sys_open and sys_openat2 kprobes to avoid duplication
// VFS layer already captures the essential file system structure changes
// If specific syscall monitoring is needed, it should be in a separate 
// syscall-focused eBPF program, not mixed with VFS monitoring