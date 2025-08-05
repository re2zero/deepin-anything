// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VFS_LAYER_MONITOR_H
#define VFS_LAYER_MONITOR_H

#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include "../include/ebpf_common.h"

struct bpf_object;
struct bpf_link;
struct ring_buffer;

namespace ebpf {

class VFSLayerMonitor {
public:
    VFSLayerMonitor();
    ~VFSLayerMonitor();

    bool initialize();
    bool start();
    void stop();
    
    void setEventHandler(std::function<void(const vfs_event&)> handler);

private:
    bool loadVFSProgram();
    bool attachKprobes();
    void detachKprobes();
    
    void ringBufferPollLoop();
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz);

private:
    struct bpf_object *obj_;
    struct bpf_link *vfs_create_link_;
    struct bpf_link *vfs_mkdir_link_;
    struct bpf_link *vfs_unlink_link_;
    struct bpf_link *vfs_rmdir_link_;
    struct bpf_link *vfs_rename_link_;
    
    struct ring_buffer *rb_;
    std::thread poll_thread_;
    std::atomic<bool> running_;
    
    std::function<void(const vfs_event&)> event_handler_;
    bool initialized_;
};

} // namespace ebpf

#endif // VFS_LAYER_MONITOR_H