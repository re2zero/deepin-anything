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
} mmap_events SEC(".maps");

// Map to track file descriptors to paths
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);    // fd + pid
    __type(value, char[256]); // path
} fd_to_path SEC(".maps");

// Map to track memory mappings
struct mmap_info {
    __u64 addr;
    __u64 size;
    __u32 pid;
    __u32 fd;
    char path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);    // address
    __type(value, struct mmap_info);
} addr_to_mapping SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Helper function to send mmap event to userspace
static __always_inline void send_mmap_event(__u8 action, const char *path, __u32 source_type) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&mmap_events, sizeof(*event), 0);
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
    event->source_type = source_type; // MMAP_SOURCE = 2
    
    // Get process information
    get_process_info(event);
    
    // Copy path
    if (path) {
        bpf_probe_read_str(event->path, sizeof(event->path), path);
    } else {
        bpf_probe_read_str(event->path, sizeof(event->path), "<mmap_operation>");
    }
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// Simplified mmap monitoring using basic kprobes
// For demonstration purposes, we'll just generate events when mmap operations occur

SEC("kprobe/sys_mmap")
int trace_mmap(struct pt_regs *ctx) {
    // Generate a simple mmap event
    send_mmap_event(ACT_NEW_FILE, NULL, MMAP_SOURCE);
    return 0;
}

SEC("kprobe/sys_munmap")
int trace_munmap(struct pt_regs *ctx) {
    // Generate a simple munmap event
    send_mmap_event(ACT_DEL_FILE, NULL, MMAP_SOURCE);
    return 0;
}

SEC("kprobe/sys_msync")
int trace_msync(struct pt_regs *ctx) {
    // Generate a file modification event for msync
    send_mmap_event(ACT_RENAME_FILE, NULL, MMAP_SOURCE); // Use rename as "modify"
    return 0;
}

// Note: For a complete implementation, we would also need:
// - sys_exit_openat to capture the returned fd and map it to the path
// - Handling of close() to clean up fd_to_path mappings
// - More sophisticated tracking of memory regions and page faults 