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
extern unsigned char vfs_monitor_enhanced_o[];
extern unsigned int vfs_monitor_enhanced_o_len;

namespace ebpf {

class VFSLayerMonitor {
public:
    VFSLayerMonitor() : obj_(nullptr), ring_buf_(nullptr), is_running_(false) {}
    ~VFSLayerMonitor();

    // Initialize the VFS layer monitor
    bool initialize();
    
    // Start monitoring VFS layer events
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
    bool loadVFSProgram();
    bool attachKprobes();
    void detachKprobes();
    void ringBufferPollLoop();
    
    // Static callback for ring buffer events
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz);
};

} // namespace ebpf