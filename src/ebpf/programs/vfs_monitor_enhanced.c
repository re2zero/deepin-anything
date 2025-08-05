// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ebpf_common.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Helper function to send event to userspace (simplified for VFS)
static __always_inline void send_vfs_event(__u8 action, __u32 source_type) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
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
    
    // Use a simple VFS operation indicator
    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_operation>");
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// Simplified VFS monitoring using basic kprobes
// Note: These are simplified implementations for demonstration
// A production version would need proper path extraction from kernel structures

// For VFS functions, we need to extract path differently since they don't take filename directly
// We'll use a simplified approach and get the path from process context when possible

SEC("kprobe/vfs_create")
int trace_vfs_create(struct pt_regs *ctx) {
    // VFS functions work with dentry structures, path extraction is complex
    // For now, we'll generate events to show VFS layer activity
    send_vfs_event(ACT_NEW_FILE, VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_mkdir")
int trace_vfs_mkdir(struct pt_regs *ctx) {
    send_vfs_event(ACT_NEW_FILE, VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_unlink")
int trace_vfs_unlink(struct pt_regs *ctx) {
    send_vfs_event(ACT_DEL_FILE, VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_rmdir")
int trace_vfs_rmdir(struct pt_regs *ctx) {
    send_vfs_event(ACT_DEL_FILE, VFS_SOURCE);
    return 0;
}

SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
    send_vfs_event(ACT_RENAME_FROM, VFS_SOURCE);
    return 0;
}