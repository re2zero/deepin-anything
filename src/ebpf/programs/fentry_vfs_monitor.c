// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/ebpf_common.h"

// Type definitions for kernel compatibility
typedef unsigned short umode_t;
typedef _Bool bool;

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} fentry_vfs_events SEC(".maps");

// Struct definitions for kernel types (using CO-RE for compatibility)
struct qstr {
    const unsigned char *name;
    unsigned int len;
};

struct dentry {
    struct qstr d_name;
    // ... other fields omitted for brevity
};

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Optimized path extraction from dentry using fentry
static __always_inline int extract_filename_from_dentry(struct dentry *dentry, char *path_buf, int buf_size) {
    if (!dentry) {
        return -1;
    }
    
    struct qstr d_name;
    int ret = bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name);
    if (ret != 0) {
        return -1;
    }
    
    if (!d_name.name || d_name.len == 0) {
        return -1;
    }
    
    // Limit the length to avoid eBPF verifier issues
    int copy_len = d_name.len;
    if (copy_len > buf_size - 1) {
        copy_len = buf_size - 1;
    }
    if (copy_len > 255) {  // Additional safety limit
        copy_len = 255;
    }
    
    ret = bpf_core_read_str(path_buf, copy_len + 1, d_name.name);
    return ret > 0 ? 0 : -1;
}

// Enhanced event sender with filename extraction
static __always_inline void send_fentry_vfs_event(__u8 action, struct dentry *dentry, const char* fallback_name) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&fentry_vfs_events, sizeof(*event), 0);
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
    
    // Try to extract filename from dentry
    if (extract_filename_from_dentry(dentry, event->path, sizeof(event->path)) != 0) {
        // Fallback to operation name
        if (fallback_name) {
            bpf_probe_read_str(event->path, sizeof(event->path), fallback_name);
        } else {
            switch (action) {
                case ACT_NEW_FILE:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<create>");
                    break;
                case ACT_NEW_FOLDER:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<mkdir>");
                    break;
                case ACT_DEL_FILE:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<unlink>");
                    break;
                case ACT_DEL_FOLDER:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<rmdir>");
                    break;
                case ACT_RENAME_FROM:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<rename>");
                    break;
                default:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_op>");
                    break;
            }
        }
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// fentry hooks for VFS functions with direct parameter access
// These have access to the actual function parameters, not just pt_regs

SEC("fentry/vfs_create")
int BPF_PROG(fentry_vfs_create, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int want_excl) {
    send_fentry_vfs_event(ACT_NEW_FILE, (struct dentry*)dentry, "create");
    return 0;
}

SEC("fentry/vfs_mkdir")
int BPF_PROG(fentry_vfs_mkdir, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode) {
    send_fentry_vfs_event(ACT_NEW_FOLDER, (struct dentry*)dentry, "mkdir");
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink, void *mnt_userns, void *dir, void *dentry, 
             void *delegated_inode) {
    send_fentry_vfs_event(ACT_DEL_FILE, (struct dentry*)dentry, "unlink");
    return 0;
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(fentry_vfs_rmdir, void *mnt_userns, void *dir, void *dentry) {
    send_fentry_vfs_event(ACT_DEL_FOLDER, (struct dentry*)dentry, "rmdir");
    return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename, struct renamedata *rd) {
    // Extract old_dentry from renamedata structure
    struct dentry *old_dentry;
    int ret = bpf_core_read(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
    if (ret == 0) {
        send_fentry_vfs_event(ACT_RENAME_FROM, old_dentry, "rename");
    } else {
        send_fentry_vfs_event(ACT_RENAME_FROM, NULL, "rename");
    }
    return 0;
}

SEC("fentry/vfs_link")
int BPF_PROG(fentry_vfs_link, struct dentry *old_dentry, struct user_namespace *mnt_userns,
             struct inode *dir, struct dentry *new_dentry, struct inode **delegated_inode) {
    send_fentry_vfs_event(ACT_NEW_LINK, new_dentry, "link");
    return 0;
}

SEC("fentry/vfs_symlink")
int BPF_PROG(fentry_vfs_symlink, struct user_namespace *mnt_userns,
             struct inode *dir, struct dentry *dentry, const char *oldname) {
    send_fentry_vfs_event(ACT_NEW_SYMLINK, dentry, "symlink");
    return 0;
}

// Optional: syscall-level fentry hooks for path extraction
// These can provide full path information at the cost of some performance

SEC("fentry/do_sys_openat2")
int BPF_PROG(fentry_sys_openat2, int dfd, const char __user *filename, struct open_how *how) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&fentry_vfs_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = ACT_NEW_FILE; // Simplified, should check flags
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = SYSCALL_SOURCE;
    
    // Get process information
    get_process_info(event);
    
    // Extract the real file path from syscall argument
    if (filename) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), filename);
    } else {
        bpf_probe_read_str(event->path, sizeof(event->path), "<unknown_path>");
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Note: fentry provides significant advantages:
// 1. Direct access to typed function parameters (no PT_REGS parsing)
// 2. Better performance than kprobes (~20-30% faster)
// 3. Type safety with BPF_PROG macro
// 4. Easier to extract dentry information
// 5. Requires kernel 5.5+ and BTF support 