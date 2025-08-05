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
} hybrid_events SEC(".maps");

// Event success/failure tracking
#define EVENT_SUCCESS 0
#define EVENT_FAILURE 1
#define EVENT_ATTEMPT 2

// Helper function to get current process info
static __always_inline void get_process_info(struct vfs_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// Enhanced event sender with success/failure indication
static __always_inline void send_hybrid_event(__u8 action, const char* operation, 
                                               __u32 status, int error_code) {
    struct vfs_event *event;
    
    event = bpf_ringbuf_reserve(&hybrid_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    
    // Initialize event
    event->pid = 0;
    event->uid = 0;
    event->action = action;
    event->cookie = status;  // 借用cookie字段存储状态
    event->major = error_code; // 借用major字段存储错误码
    event->minor = 0;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = VFS_SOURCE;
    
    get_process_info(event);
    
    // 构造描述性路径
    char status_prefix[32];
    switch(status) {
        case EVENT_SUCCESS:
            bpf_probe_read_str(status_prefix, sizeof(status_prefix), "[SUCCESS]");
            break;
        case EVENT_FAILURE:
            bpf_probe_read_str(status_prefix, sizeof(status_prefix), "[FAILED]");
            break;
        case EVENT_ATTEMPT:
            bpf_probe_read_str(status_prefix, sizeof(status_prefix), "[ATTEMPT]");
            break;
        default:
            bpf_probe_read_str(status_prefix, sizeof(status_prefix), "[UNKNOWN]");
            break;
    }
    
    // 组合状态和操作名
    if (operation) {
        bpf_probe_read_str(event->path, sizeof(event->path), operation);
    } else {
        bpf_probe_read_str(event->path, sizeof(event->path), "[HYBRID_OP]");
    }
    
    bpf_ringbuf_submit(event, 0);
}

// ==================== FENTRY HOOKS (函数入口) ====================
// 这些在操作尝试时触发，不知道结果

SEC("fentry/vfs_create")
int BPF_PROG(fentry_vfs_create, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int want_excl) {
    send_hybrid_event(ACT_NEW_FILE, "fentry_create_attempt", EVENT_ATTEMPT, 0);
    return 0;
}

SEC("fentry/vfs_mkdir")
int BPF_PROG(fentry_vfs_mkdir, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode) {
    send_hybrid_event(ACT_NEW_FOLDER, "fentry_mkdir_attempt", EVENT_ATTEMPT, 0);
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(fentry_vfs_unlink, void *mnt_userns, void *dir, void *dentry, 
             void *delegated_inode) {
    send_hybrid_event(ACT_DEL_FILE, "fentry_unlink_attempt", EVENT_ATTEMPT, 0);
    return 0;
}

// ==================== FEXIT HOOKS (函数退出) ====================
// 这些在操作完成后触发，知道结果

SEC("fexit/vfs_create")
int BPF_PROG(fexit_vfs_create, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int want_excl, int ret) {
    if (ret == 0) {
        send_hybrid_event(ACT_NEW_FILE, "fexit_create_success", EVENT_SUCCESS, 0);
    } else {
        send_hybrid_event(ACT_NEW_FILE, "fexit_create_failed", EVENT_FAILURE, ret);
    }
    return 0;
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(fexit_vfs_mkdir, void *mnt_userns, void *dir, void *dentry, 
             unsigned int mode, int ret) {
    if (ret == 0) {
        send_hybrid_event(ACT_NEW_FOLDER, "fexit_mkdir_success", EVENT_SUCCESS, 0);
    } else {
        send_hybrid_event(ACT_NEW_FOLDER, "fexit_mkdir_failed", EVENT_FAILURE, ret);
    }
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit_vfs_unlink, void *mnt_userns, void *dir, void *dentry, 
             void *delegated_inode, int ret) {
    if (ret == 0) {
        send_hybrid_event(ACT_DEL_FILE, "fexit_unlink_success", EVENT_SUCCESS, 0);
    } else {
        send_hybrid_event(ACT_DEL_FILE, "fexit_unlink_failed", EVENT_FAILURE, ret);
    }
    return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(fexit_vfs_rmdir, void *mnt_userns, void *dir, void *dentry, int ret) {
    if (ret == 0) {
        send_hybrid_event(ACT_DEL_FOLDER, "fexit_rmdir_success", EVENT_SUCCESS, 0);
    } else {
        send_hybrid_event(ACT_DEL_FOLDER, "fexit_rmdir_failed", EVENT_FAILURE, ret);
    }
    return 0;
}

// ==================== SYSCALL LEVEL MONITORING ====================
// 用于获取完整路径信息

SEC("fexit/do_sys_openat2")
int BPF_PROG(fexit_sys_openat2, int dfd, void *filename, void *how, long ret) {
    struct vfs_event *event;
    
    event = bpf_ringbuf_reserve(&hybrid_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = 0;
    event->uid = 0;
    event->action = ACT_NEW_FILE;
    event->timestamp = bpf_ktime_get_ns();
    event->source_type = SYSCALL_SOURCE;
    
    get_process_info(event);
    
    // 根据返回值判断成功/失败
    if (ret >= 0) {  // 成功：返回文件描述符
        event->cookie = EVENT_SUCCESS;
        event->major = ret;  // 文件描述符
        // 尝试提取路径
        if (filename) {
            bpf_probe_read_user_str(event->path, sizeof(event->path), 
                                   (const char __user*)filename);
        } else {
            bpf_probe_read_str(event->path, sizeof(event->path), 
                              "fexit_openat2_success_no_path");
        }
    } else {  // 失败：负数错误码
        event->cookie = EVENT_FAILURE;
        event->major = -ret;  // 错误码
        bpf_probe_read_str(event->path, sizeof(event->path), 
                          "fexit_openat2_failed");
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Note: Fentry vs Fexit 比较总结
// 
// 🔥 最佳实践建议：
// 1. 仅使用 FEXIT 进行生产监控 - 只记录成功的操作
// 2. 使用 FENTRY+FEXIT 进行调试 - 了解操作尝试和结果
// 3. 使用 FEXIT/do_sys_openat2 获取准确的路径+结果
// 
// 🎯 性能考虑：
// - Fexit 比 Fentry 略慢（需要等函数执行完成）
// - 但避免了无效事件，减少了用户空间处理负担
// - 总体效率更高 