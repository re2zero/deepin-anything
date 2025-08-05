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
} fexit_fs_events SEC(".maps");

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

// VFS layer event sender - 专注于文件系统结构变化
static __always_inline void send_vfs_structure_event(__u8 action, const char* operation_name) {
    struct vfs_event *event;
    
    event = bpf_ringbuf_reserve(&fexit_fs_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 0;  // VFS层标识
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
        copy_string(event->path, "fexit_fs_change", MAX_PATH_LEN);
    }
    
    bpf_ringbuf_submit(event, 0);
}

// Syscall layer event sender - 只监控结构变化的系统调用
static __always_inline void send_syscall_structure_event(__u8 action, void *filename_ptr, 
                                                         const char* fallback) {
    struct vfs_event *event;
    
    event = bpf_ringbuf_reserve(&fexit_fs_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = 1;  // Syscall层有路径标识
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
        long ret = bpf_probe_read_user_str(event->path, MAX_PATH_LEN, filename_ptr);
        if (ret < 0) {
            if (fallback) {
                copy_string(event->path, fallback, MAX_PATH_LEN);
            } else {
                copy_string(event->path, "fexit_path_read_failed", MAX_PATH_LEN);
            }
        }
    } else {
        if (fallback) {
            copy_string(event->path, fallback, MAX_PATH_LEN);
        } else {
            copy_string(event->path, "fexit_no_filename", MAX_PATH_LEN);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
}

// ==================== VFS LAYER FEXIT HOOKS ====================
// 🎯 只监控文件系统结构变化，不监控内容访问

SEC("fexit/vfs_create")
int BPF_PROG(fexit_vfs_create, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int want_excl, int ret) {
    if (ret == 0) {
        send_vfs_structure_event(ACT_NEW_FILE, "fexit_create");
    }
    return 0;
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(fexit_vfs_mkdir, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int ret) {
    if (ret == 0) {
        send_vfs_structure_event(ACT_NEW_FOLDER, "fexit_mkdir");
    }
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit_vfs_unlink, void *mnt_userns, void *dir, void *dentry, 
             void *delegated_inode, int ret) {
    if (ret == 0) {
        send_vfs_structure_event(ACT_DEL_FILE, "fexit_unlink");
    }
    return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(fexit_vfs_rmdir, void *mnt_userns, void *dir, void *dentry, int ret) {
    if (ret == 0) {
        send_vfs_structure_event(ACT_DEL_FOLDER, "fexit_rmdir");
    }
    return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit_vfs_rename, void *rd, int ret) {
    if (ret == 0) {
        send_vfs_structure_event(ACT_RENAME_FROM, "fexit_rename");
    }
    return 0;
}

// ==================== SYSCALL LAYER FEXIT HOOKS ====================
// 🎯 重要：只监控创建新文件的操作，不监控已有文件的打开

// 只监控文件创建（O_CREAT标志）的openat2
// 注意：这里我们需要区分创建和打开，但由于eBPF限制，暂时监控所有成功的打开
// 在用户空间可以根据路径特征过滤（如排除/proc、/sys等）

SEC("fexit/do_sys_openat2")
int BPF_PROG(fexit_sys_openat2, int dfd, void *filename, void *how, long ret) {
    // 只记录成功的文件操作
    if (ret >= 0) {
        // 注意：这里会捕获所有文件打开，包括读取现有文件
        // 用户空间需要根据路径和上下文进一步过滤
        send_syscall_structure_event(ACT_NEW_FILE, filename, "fexit_openat2");
    }
    return 0;
}

// 移除 do_sys_open 监控以减少重复事件
// SEC("fexit/do_sys_open") 已移除

// Note: 文件系统监控优化策略
// 
// 🎯 监控目标：
// - ✅ 文件/目录创建 (vfs_create, vfs_mkdir)
// - ✅ 文件/目录删除 (vfs_unlink, vfs_rmdir)  
// - ✅ 文件/目录重命名 (vfs_rename)
// - ❌ 文件内容读写 (不监控 vfs_read, vfs_write)
// - ❌ 文件属性访问 (不监控 getattr, setattr)
//
// 🚀 事件过滤建议（用户空间）：
// - 排除系统路径：/proc/*、/sys/*、/dev/*
// - 排除临时文件：*.tmp、*.swp、*.log
// - 专注用户数据：/home/*、/var/*、/opt/*
//
// 💡 性能优化：
// - VFS层：快速检测结构变化
// - Syscall层：获取关键操作的完整路径
// - 双重过滤：内核层基础过滤 + 用户空间智能过滤 