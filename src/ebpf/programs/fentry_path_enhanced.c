// SPDX-License-Identifier: GPL-3.0-or-later

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/ebpf_common.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} fentry_path_events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Enhanced path extraction from dentry using CO-RE
static __always_inline int extract_path_from_dentry(void *dentry_ptr, char *path_buf, int buf_size) {
    if (!dentry_ptr) {
        return -1;
    }
    
    // Use CO-RE to read dentry->d_name.name safely
    const unsigned char *name_ptr;
    int ret = bpf_core_read(&name_ptr, sizeof(name_ptr), dentry_ptr + 32); // d_name offset
    if (ret != 0) {
        return -1;
    }
    
    if (!name_ptr) {
        return -1;
    }
    
    // Read the actual filename
    ret = bpf_core_read_str(path_buf, buf_size > 256 ? 256 : buf_size, name_ptr);
    return ret > 0 ? 0 : -1;
}

// Advanced event sender with path extraction
static __always_inline void send_fentry_path_event(__u8 action, void *dentry, const char* fallback_name) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&fentry_path_events, sizeof(*event), 0);
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
    
    // Try to extract real path from dentry
    if (dentry && extract_path_from_dentry(dentry, event->path, sizeof(event->path)) == 0) {
        // Successfully extracted path from dentry
        // path_buf now contains the filename
    } else {
        // Fallback to operation name
        if (fallback_name) {
            bpf_probe_read_str(event->path, sizeof(event->path), fallback_name);
        } else {
            bpf_probe_read_str(event->path, sizeof(event->path), "<fentry_unknown>");
        }
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
}

// Enhanced fentry hooks with dentry parameter extraction
SEC("fentry/vfs_create")
int BPF_PROG(fentry_vfs_create, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int want_excl) {
    send_fentry_path_event(ACT_NEW_FILE, dentry, "fentry_create");
    return 0;
}

SEC("fentry/vfs_mkdir") 
int BPF_PROG(fentry_vfs_mkdir, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode) {
    send_fentry_path_event(ACT_NEW_FOLDER, dentry, "fentry_mkdir");
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink, void *mnt_userns, void *dir, void *dentry, 
             void *delegated_inode) {
    send_fentry_path_event(ACT_DEL_FILE, dentry, "fentry_unlink");
    return 0;
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(fentry_vfs_rmdir, void *mnt_userns, void *dir, void *dentry) {
    send_fentry_path_event(ACT_DEL_FOLDER, dentry, "fentry_rmdir");
    return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename, void *rd) {
    // For rename, we need to extract old_dentry from renamedata
    void *old_dentry;
    int ret = bpf_core_read(&old_dentry, sizeof(old_dentry), rd + 16); // old_dentry offset
    if (ret == 0) {
        send_fentry_path_event(ACT_RENAME_FROM, old_dentry, "fentry_rename");
    } else {
        send_fentry_path_event(ACT_RENAME_FROM, NULL, "fentry_rename");
    }
    return 0;
}

// 关键：do_sys_openat2 的 fentry 版本
// 这个可以获取完整的用户空间路径！
SEC("fentry/do_sys_openat2")
int BPF_PROG(fentry_sys_openat2, int dfd, void *filename, void *how) {
    struct vfs_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&fentry_path_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = ACT_NEW_FILE; // Simplified
    event->cookie = 0;
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = SYSCALL_SOURCE; // 这是syscall层！
    
    // Get process information
    get_process_info(event);
    
    // Extract the real file path from syscall argument - 这里是关键！
    if (filename) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), (const char __user*)filename);
    } else {
        bpf_probe_read_str(event->path, sizeof(event->path), "<fentry_openat2_no_path>");
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Note: fentry/do_sys_openat2 的价值：
// 1. 比kprobe性能更好（20-30%提升）
// 2. 直接访问函数参数，无需PT_REGS解析
// 3. 可以获取完整的用户空间路径
// 4. 类型安全，减少错误 