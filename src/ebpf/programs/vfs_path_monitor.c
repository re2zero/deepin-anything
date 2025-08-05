// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/ebpf_common.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} vfs_path_events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Optimized helper to extract basic path from dentry (simplified approach)
static __always_inline int extract_path_from_dentry(void *dentry_ptr, char *path_buf, int buf_size) {
    // This is a simplified approach - in real implementation, we'd need to
    // traverse the dentry tree, but eBPF limitations make this complex
    // For now, we'll extract just the immediate filename
    
    if (!dentry_ptr) {
        return -1;
    }
    
    // Use BPF CO-RE to safely access dentry->d_name.name
    // Note: This requires proper BTF support and may not work on all kernels
    struct qstr d_name;
    int ret = bpf_core_read(&d_name, sizeof(d_name), dentry_ptr + 32); // Approximate d_name offset
    if (ret != 0) {
        return -1;
    }
    
    // Read the filename
    ret = bpf_core_read_str(path_buf, buf_size > 256 ? 256 : buf_size, d_name.name);
    return ret > 0 ? 0 : -1;
}

// Optimized event sender with path extraction attempt
static __always_inline void send_vfs_path_event(__u8 action, void *dentry_ptr, const char* fallback_name) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&vfs_path_events, sizeof(*event), 0);
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
    
    // Try to extract path from dentry, fallback to operation name
    if (extract_path_from_dentry(dentry_ptr, event->path, sizeof(event->path)) != 0) {
        // Fallback to operation descriptor
        if (fallback_name) {
            bpf_probe_read_str(event->path, sizeof(event->path), fallback_name);
        } else {
            // Generate descriptive path based on action
            switch (action) {
                case ACT_NEW_FILE:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_create>");
                    break;
                case ACT_NEW_FOLDER:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_mkdir>");
                    break;
                case ACT_DEL_FILE:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_unlink>");
                    break;
                case ACT_DEL_FOLDER:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_rmdir>");
                    break;
                case ACT_RENAME_FROM:
                    bpf_probe_read_str(event->path, sizeof(event->path), "<vfs_rename>");
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

// VFS kprobes with attempted path extraction
// Note: These functions try to extract dentry from function arguments

SEC("kprobe/vfs_create")
int trace_vfs_create(struct pt_regs *ctx) {
    // vfs_create signature: int vfs_create(struct user_namespace *, struct inode *, struct dentry *, umode_t, bool)
    void *dentry = (void *)PT_REGS_PARM3(ctx);
    send_vfs_path_event(ACT_NEW_FILE, dentry, "<create>");
    return 0;
}

SEC("kprobe/vfs_mkdir") 
int trace_vfs_mkdir(struct pt_regs *ctx) {
    // vfs_mkdir signature: int vfs_mkdir(struct user_namespace *, struct inode *, struct dentry *, umode_t)
    void *dentry = (void *)PT_REGS_PARM3(ctx);
    send_vfs_path_event(ACT_NEW_FOLDER, dentry, "<mkdir>");
    return 0;
}

SEC("kprobe/vfs_unlink")
int trace_vfs_unlink(struct pt_regs *ctx) {
    // vfs_unlink signature: int vfs_unlink(struct user_namespace *, struct inode *, struct dentry *, struct inode **)
    void *dentry = (void *)PT_REGS_PARM3(ctx);
    send_vfs_path_event(ACT_DEL_FILE, dentry, "<unlink>");
    return 0;
}

SEC("kprobe/vfs_rmdir")
int trace_vfs_rmdir(struct pt_regs *ctx) {
    // vfs_rmdir signature: int vfs_rmdir(struct user_namespace *, struct inode *, struct dentry *)
    void *dentry = (void *)PT_REGS_PARM3(ctx);
    send_vfs_path_event(ACT_DEL_FOLDER, dentry, "<rmdir>");
    return 0;
}

SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
    // vfs_rename signature is complex, we'll try to get old_dentry 
    void *old_dentry = (void *)PT_REGS_PARM3(ctx); // Approximate
    send_vfs_path_event(ACT_RENAME_FROM, old_dentry, "<rename>");
    return 0;
}

// Note: This approach attempts to balance performance with path extraction
// It may not work on all kernel versions due to dentry structure changes
// For production use, additional BTF-based validation would be needed 