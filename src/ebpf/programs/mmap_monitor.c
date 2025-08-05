// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
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
} mmap_events SEC(".maps");

// Hash map to track file descriptors to paths
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // file descriptor
    __type(value, char[256]); // file path
} fd_to_path SEC(".maps");

// Hash map to track memory mappings
struct mapping_info {
    __u64 addr;
    __u64 size;
    __u32 fd;
    __u32 pid;
    char path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);    // memory address
    __type(value, struct mapping_info);
} addr_to_mapping SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Helper function to send mmap event to userspace
static __always_inline void send_mmap_event(__u8 action, const char* path_hint, __u32 source_type) {
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
    
    // Set path information
    if (path_hint) {
        bpf_probe_read_str(event->path, sizeof(event->path), path_hint);
    } else {
        // Generate descriptive path for mmap operations
        switch (action) {
            case ACT_NEW_FILE:
                bpf_probe_read_str(event->path, sizeof(event->path), "<mmap_file>");
                break;
            case ACT_DEL_FILE:
                bpf_probe_read_str(event->path, sizeof(event->path), "<munmap_file>");
                break;
            case ACT_RENAME_FILE:
                bpf_probe_read_str(event->path, sizeof(event->path), "<msync_file>");
                break;
            default:
                bpf_probe_read_str(event->path, sizeof(event->path), "<mmap_operation>");
                break;
        }
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// Kprobe for sys_mmap - enhanced version
SEC("kprobe/sys_mmap")
int trace_mmap(struct pt_regs *ctx) {
    __u64 addr = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    __u32 prot = PT_REGS_PARM3(ctx);
    __u32 flags = PT_REGS_PARM4(ctx);
    __u32 fd = PT_REGS_PARM5(ctx);
    __u64 offset = PT_REGS_PARM6(ctx);
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Try to get path from fd_to_path map
    char *path = bpf_map_lookup_elem(&fd_to_path, &fd);
    
    // Create mapping info
    struct mapping_info mapping = {};
    mapping.addr = addr;
    mapping.size = size;
    mapping.fd = fd;
    mapping.pid = pid;
    
    if (path) {
        // Copy path from map
        #pragma unroll
        for (int i = 0; i < 255; i++) {
            mapping.path[i] = path[i];
            if (path[i] == '\0') break;
        }
        mapping.path[255] = '\0';
        
        // Send event with actual path
        send_mmap_event(ACT_NEW_FILE, path, MMAP_SOURCE);
    } else {
        // Unknown file, use generic path
        bpf_probe_read_str(mapping.path, sizeof(mapping.path), "<mmap_unknown>");
        send_mmap_event(ACT_NEW_FILE, NULL, MMAP_SOURCE);
    }
    
    // Store mapping info for later reference
    bpf_map_update_elem(&addr_to_mapping, &addr, &mapping, BPF_ANY);
    
    return 0;
}

// Kprobe for sys_munmap - enhanced version
SEC("kprobe/sys_munmap")
int trace_munmap(struct pt_regs *ctx) {
    __u64 addr = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    
    // Look up mapping info
    struct mapping_info *mapping = bpf_map_lookup_elem(&addr_to_mapping, &addr);
    
    if (mapping) {
        // Send event with mapping path
        send_mmap_event(ACT_DEL_FILE, mapping->path, MMAP_SOURCE);
        
        // Remove mapping from map
        bpf_map_delete_elem(&addr_to_mapping, &addr);
    } else {
        // Unknown mapping
        send_mmap_event(ACT_DEL_FILE, NULL, MMAP_SOURCE);
    }
    
    return 0;
}

// Kprobe for sys_msync - enhanced version
SEC("kprobe/sys_msync")
int trace_msync(struct pt_regs *ctx) {
    __u64 addr = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    __u32 flags = PT_REGS_PARM3(ctx);
    
    // Look up mapping info
    struct mapping_info *mapping = bpf_map_lookup_elem(&addr_to_mapping, &addr);
    
    if (mapping) {
        // Send sync event with mapping path
        send_mmap_event(ACT_RENAME_FILE, mapping->path, MMAP_SOURCE);
    } else {
        // Unknown mapping
        send_mmap_event(ACT_RENAME_FILE, NULL, MMAP_SOURCE);
    }
    
    return 0;
}

// Additional kprobes for file descriptor tracking
SEC("kprobe/do_sys_open")
int trace_sys_open(struct pt_regs *ctx) {
    // This will help us track fd->path mappings
    // Note: In a real implementation, we'd need to capture the return value
    // and the filename parameter, but this is simplified for demonstration
    return 0;
}

// Kprobe for memory protection changes
SEC("kprobe/sys_mprotect")
int trace_mprotect(struct pt_regs *ctx) {
    __u64 addr = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    __u32 prot = PT_REGS_PARM3(ctx);
    
    // Look up mapping info
    struct mapping_info *mapping = bpf_map_lookup_elem(&addr_to_mapping, &addr);
    
    if (mapping) {
        // Send protection change event
        send_mmap_event(ACT_RENAME_FILE, mapping->path, MMAP_SOURCE);
    } else {
        // Unknown mapping
        send_mmap_event(ACT_RENAME_FILE, "<mprotect_unknown>", MMAP_SOURCE);
    }
    
    return 0;
} 