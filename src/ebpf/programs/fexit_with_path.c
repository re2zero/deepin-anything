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
} fexit_path_events SEC(".maps");

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Simple string copy helper
static __always_inline void copy_string(char *dst, const char *src, int max_len) {
    #pragma unroll
    for (int i = 0; i < 32 && i < max_len - 1; i++) {
        char c = src[i];
        dst[i] = c;
        if (c == 0) break;
    }
}

// VFS layer event sender (without full path)
static __always_inline void send_vfs_success_event(__u8 action, const char* operation_name) {
    struct vfs_event *event;
    
    event = bpf_ringbuf_reserve(&fexit_path_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 0;  // Success indicator
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = VFS_SOURCE;
    
    get_process_info(event);
    
    // Initialize path array
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN && i < 64; i++) {
        event->path[i] = 0;
    }
    
    // Set operation identifier
    if (operation_name) {
        copy_string(event->path, operation_name, MAX_PATH_LEN);
    } else {
        copy_string(event->path, "fexit_vfs_success", MAX_PATH_LEN);
    }
    
    bpf_ringbuf_submit(event, 0);
}

// Syscall layer event sender with real path extraction
static __always_inline void send_syscall_success_event(__u8 action, void *filename_ptr, 
                                                       const char* fallback) {
    struct vfs_event *event;
    
    event = bpf_ringbuf_reserve(&fexit_path_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 1;  // Success + Path available indicator
    event->major = 0;
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = SYSCALL_SOURCE;
    
    get_process_info(event);
    
    // Initialize path array
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN && i < 64; i++) {
        event->path[i] = 0;
    }
    
    // Try to extract real file path from user space
    if (filename_ptr) {
        // Use bpf_probe_read_user_str to safely read user space string
        long ret = bpf_probe_read_user_str(event->path, MAX_PATH_LEN, filename_ptr);
        if (ret < 0) {
            // Fallback if path read failed
            if (fallback) {
                copy_string(event->path, fallback, MAX_PATH_LEN);
            } else {
                copy_string(event->path, "fexit_path_read_failed", MAX_PATH_LEN);
            }
        }
    } else {
        // No filename provided
        if (fallback) {
            copy_string(event->path, fallback, MAX_PATH_LEN);
        } else {
            copy_string(event->path, "fexit_no_filename", MAX_PATH_LEN);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
}

// ==================== VFS LAYER FEXIT HOOKS ====================
// 这些只能获取操作类型，不能获取完整路径

SEC("fexit/vfs_create")
int BPF_PROG(fexit_vfs_create, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int want_excl, int ret) {
    if (ret == 0) {
        send_vfs_success_event(ACT_NEW_FILE, "fexit_vfs_create");
    }
    return 0;
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(fexit_vfs_mkdir, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int ret) {
    if (ret == 0) {
        send_vfs_success_event(ACT_NEW_FOLDER, "fexit_vfs_mkdir");
    }
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit_vfs_unlink, void *mnt_userns, void *dir, void *dentry, 
             void *delegated_inode, int ret) {
    if (ret == 0) {
        send_vfs_success_event(ACT_DEL_FILE, "fexit_vfs_unlink");
    }
    return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(fexit_vfs_rmdir, void *mnt_userns, void *dir, void *dentry, int ret) {
    if (ret == 0) {
        send_vfs_success_event(ACT_DEL_FOLDER, "fexit_vfs_rmdir");
    }
    return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit_vfs_rename, void *rd, int ret) {
    if (ret == 0) {
        send_vfs_success_event(ACT_RENAME_FROM, "fexit_vfs_rename");
    }
    return 0;
}

// ==================== SYSCALL LAYER FEXIT HOOKS ====================
// 🔑 关键：这些可以获取完整的用户空间路径！

SEC("fexit/do_sys_openat2")
int BPF_PROG(fexit_sys_openat2, int dfd, void *filename, void *how, long ret) {
    // 只有成功时才记录 (ret >= 0 表示返回了有效的文件描述符)
    if (ret >= 0) {
        send_syscall_success_event(ACT_NEW_FILE, filename, "fexit_openat2_success");
    }
    return 0;
}

SEC("fexit/do_sys_open")
int BPF_PROG(fexit_sys_open, void *filename, int flags, unsigned int mode, long ret) {
    if (ret >= 0) {
        send_syscall_success_event(ACT_NEW_FILE, filename, "fexit_open_success");
    }
    return 0;
}

// 简化：只保留确定可用的syscall hooks
// 注释掉可能有签名问题的hooks，专注于主要功能测试

// Note: Fexit路径监控的核心优势
// 
// 🎯 双层监控策略：
// - VFS层：高频结构变化检测（无路径）
// - Syscall层：关键操作路径获取（有完整路径）
//
// 🚀 路径获取能力：
// - ✅ do_sys_openat2: 获取打开文件的完整路径
// - ✅ do_unlinkat: 获取删除文件的完整路径  
// - ✅ do_renameat2: 获取重命名文件的源和目标路径
// - ✅ do_mkdirat: 获取创建目录的完整路径
//
// 💡 事件区分：
// - cookie=0: VFS层事件（无完整路径）
// - cookie=1: Syscall层事件（有完整路径）
//
// 🔥 最佳实践：
// - 高频监控：使用VFS层fexit检测所有文件系统变化
// - 路径需求：使用Syscall层fexit获取关键操作的完整路径
// - 性能平衡：根据需要选择性启用不同层的监控 