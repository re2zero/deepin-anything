// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../include/ebpf_common.h"

// Use BTF-defined types for better compatibility
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

#define O_CREAT 00000100
#define AT_REMOVEDIR 0x200
#define S_IFDIR 0040000
#define S_ISDIR(m) (((m) & 0170000) == S_IFDIR)

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// Per-CPU array for event temporary storage to avoid stack overflow
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vfs_event);
} temp_event_map SEC(".maps");

// Tracepoint context structure for syscalls
struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

// Helper to get current timestamp
static __always_inline __u64 get_timestamp(void) {
    return bpf_ktime_get_ns();
}

// Helper to copy path safely
static __always_inline int copy_path(char *dest, const char *src, int max_len) {
    int ret = bpf_probe_read_user_str(dest, max_len, src);
    if (ret < 0) {
        dest[0] = '\0';
        return ret;
    }
    return 0;
}

// Helper to get temporary event structure
static __always_inline struct vfs_event* get_temp_event(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&temp_event_map, &key);
}

// Helper to send event to userspace
static __always_inline int send_event(struct vfs_event *event) {
    struct vfs_event *ring_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!ring_event) {
        return -12; // -ENOMEM
    }
    
    // Copy event data
    ring_event->pid = event->pid;
    ring_event->uid = event->uid;
    ring_event->action = event->action;
    ring_event->cookie = event->cookie;
    ring_event->major = event->major;
    ring_event->minor = event->minor;
    ring_event->timestamp = event->timestamp;
    
    // Copy path (limit to 256 to avoid eBPF complexity issues)
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (i >= MAX_PATH_LEN) break;
        ring_event->path[i] = event->path[i];
        if (event->path[i] == '\0') break;
    }
    
    bpf_ringbuf_submit(ring_event, 0);
    return 0;
}

// Track file creation (open with O_CREAT)
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct vfs_event *event = get_temp_event();
    if (!event) {
        return 0;
    }
    
    // Clear event structure
    event->pid = 0;
    event->uid = 0;
    event->action = 0;
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = 0;
    event->path[0] = '\0';
    
    // Get syscall arguments
    const char *pathname = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    unsigned int mode = (unsigned int)ctx->args[3];
    
    // Only track file creation
    if (!(flags & O_CREAT)) {
        return 0;
    }
    
    // Fill event data
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->timestamp = get_timestamp();
    event->cookie = 0;  // Will be set by userspace if needed
    
    // Determine if it's a directory or file based on mode
    if (S_ISDIR(mode)) {
        event->action = ACT_NEW_FOLDER;
    } else {
        event->action = ACT_NEW_FILE;
    }
    
    // Copy path
    if (copy_path(event->path, pathname, MAX_PATH_LEN) < 0) {
        return 0;
    }
    
    // Device info will be filled by userspace from fd
    event->major = 0;
    event->minor = 0;
    
    return send_event(event);
}

// Track file deletion
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct vfs_event *event = get_temp_event();
    if (!event) {
        return 0;
    }
    
    // Clear event structure
    event->pid = 0;
    event->uid = 0;
    event->action = 0;
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = 0;
    event->path[0] = '\0';
    
    // Get syscall arguments
    const char *pathname = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];
    
    // Fill event data
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->timestamp = get_timestamp();
    event->cookie = 0;
    
    // Check if it's a directory deletion
    if (flags & AT_REMOVEDIR) {
        event->action = ACT_DEL_FOLDER;
    } else {
        event->action = ACT_DEL_FILE;
    }
    
    // Copy path
    if (copy_path(event->path, pathname, MAX_PATH_LEN) < 0) {
        return 0;
    }
    
    // Device info will be determined by userspace
    event->major = 0;
    event->minor = 0;
    
    return send_event(event);
}

// Track file deletion (legacy unlink)
SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct vfs_event *event = get_temp_event();
    if (!event) {
        return 0;
    }
    
    // Clear event structure
    event->pid = 0;
    event->uid = 0;
    event->action = 0;
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = 0;
    event->path[0] = '\0';
    
    const char *pathname = (const char *)ctx->args[0];
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;
    event->timestamp = get_timestamp();
    event->cookie = 0;
    event->action = ACT_DEL_FILE;  // unlink is always for files
    
    if (copy_path(event->path, pathname, MAX_PATH_LEN) < 0) {
        return 0;
    }
    
    event->major = 0;
    event->minor = 0;
    
    return send_event(event);
}

// Track file rename
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct vfs_event *event = get_temp_event();
    if (!event) {
        return 0;
    }
    
    const char *oldpath = (const char *)ctx->args[1];
    const char *newpath = (const char *)ctx->args[3];
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u64 timestamp = get_timestamp();
    __u32 cookie = pid ^ ((__u32)timestamp);  // Generate unique cookie
    
    // Send rename_from event
    event->pid = pid;
    event->uid = uid;
    event->timestamp = timestamp;
    event->cookie = cookie;
    event->action = ACT_RENAME_FROM_FILE;
    event->major = 0;
    event->minor = 0;
    event->path[0] = '\0';
    
    if (copy_path(event->path, oldpath, MAX_PATH_LEN) == 0) {
        send_event(event);
    }
    
    // Send rename_to event
    event->action = ACT_RENAME_TO_FILE;
    event->path[0] = '\0';
    
    if (copy_path(event->path, newpath, MAX_PATH_LEN) == 0) {
        send_event(event);
    }
    
    return 0;
}

// Track file rename (legacy)
SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx) {
    struct vfs_event *event = get_temp_event();
    if (!event) {
        return 0;
    }
    
    const char *oldpath = (const char *)ctx->args[0];
    const char *newpath = (const char *)ctx->args[1];
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u64 timestamp = get_timestamp();
    __u32 cookie = pid ^ ((__u32)timestamp);
    
    // Send rename_from event
    event->pid = pid;
    event->uid = uid;
    event->timestamp = timestamp;
    event->cookie = cookie;
    event->action = ACT_RENAME_FROM_FILE;
    event->major = 0;
    event->minor = 0;
    event->path[0] = '\0';
    
    if (copy_path(event->path, oldpath, MAX_PATH_LEN) == 0) {
        send_event(event);
    }
    
    // Send rename_to event
    event->action = ACT_RENAME_TO_FILE;
    event->path[0] = '\0';
    
    if (copy_path(event->path, newpath, MAX_PATH_LEN) == 0) {
        send_event(event);
    }
    
    return 0;
} 