// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef MEMORY_MAP_MONITOR_H
#define MEMORY_MAP_MONITOR_H

#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include "../include/ebpf_common.h"

struct bpf_object;
struct bpf_link;
struct ring_buffer;

namespace ebpf {

class MemoryMapMonitor {
public:
    MemoryMapMonitor();
    ~MemoryMapMonitor();

    bool initialize();
    bool start();
    void stop();
    
    void setEventHandler(std::function<void(const vfs_event&)> handler);

private:
    bool loadMMapProgram();
    bool attachTracepoints();
    void detachTracepoints();
    
    void ringBufferPollLoop();
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz);

private:
    struct bpf_object *obj_;
    struct bpf_link *mmap_link_;
    struct bpf_link *munmap_link_;
    struct bpf_link *msync_link_;
    struct bpf_link *openat_link_;
    
    struct ring_buffer *rb_;
    std::thread poll_thread_;
    std::atomic<bool> running_;
    
    std::function<void(const vfs_event&)> event_handler_;
    bool initialized_;
};

} // namespace ebpf

#endif // MEMORY_MAP_MONITOR_H 