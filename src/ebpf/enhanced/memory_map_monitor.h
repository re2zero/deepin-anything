// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include <iostream>
#include "../include/ebpf_common.h"

// Forward declaration - bytecode will be included in .cpp file
extern unsigned char mmap_monitor_o[];
extern unsigned int mmap_monitor_o_len;

namespace ebpf {

class MemoryMapMonitor {
public:
    MemoryMapMonitor() : obj_(nullptr), ring_buf_(nullptr), is_running_(false) {}
    ~MemoryMapMonitor();

    // Initialize the memory map monitor
    bool initialize();
    
    // Start monitoring memory map events
    bool start();
    
    // Stop monitoring
    void stop();
    
    // Set event handler callback
    void setEventHandler(std::function<void(const vfs_event&)> handler);

private:
    // eBPF object and links
    struct bpf_object *obj_;
    std::vector<struct bpf_link*> kprobe_links_;  // Use vector for multiple links
    
    // Ring buffer for receiving events
    struct ring_buffer *ring_buf_;
    
    // Threading
    std::thread polling_thread_;
    std::atomic<bool> is_running_;
    
    // Event handler
    std::function<void(const vfs_event&)> event_handler_;
    
    // Internal methods
    bool loadMMapProgram();
    bool attachTracepoints();
    void detachTracepoints();
    void ringBufferPollLoop();
    
    // Static callback for ring buffer events
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz);
};

} // namespace ebpf 