// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <linux/types.h>

// Keep compatibility with existing kernel module
#define ACT_NEW_FILE         0
#define ACT_NEW_LINK         1
#define ACT_NEW_SYMLINK      2
#define ACT_NEW_FOLDER       3
#define ACT_DEL_FILE         4
#define ACT_DEL_FOLDER       5
#define ACT_RENAME_FILE      6
#define ACT_RENAME_FOLDER    7
#define ACT_RENAME_FROM_FILE 8
#define ACT_RENAME_TO_FILE   9
#define ACT_RENAME_FROM_FOLDER 10
#define ACT_RENAME_TO_FOLDER   11
#define ACT_RENAME_FROM      8  // Simplified rename from
#define ACT_RENAME_TO        9  // Simplified rename to
#define ACT_MOUNT            12
#define ACT_UNMOUNT          13

// Event source types for enhanced monitoring
#define SYSCALL_SOURCE       0
#define VFS_SOURCE          1
#define MMAP_SOURCE         2

#define MAX_PATH_LEN 4096

// Event structure compatible with existing kernel module
struct vfs_event {
    __u32 pid;
    __u32 uid;
    __u8 action;
    __u32 cookie;
    __u16 major;
    __u8 minor;
    __u64 timestamp;
    __u32 source_type;  // Added for enhanced monitoring
    char path[MAX_PATH_LEN];
} __attribute__((packed));

// Ring buffer size (256KB)
#define RINGBUF_SIZE (256 * 1024) 