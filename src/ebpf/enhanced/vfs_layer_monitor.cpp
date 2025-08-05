// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vfs_layer_monitor.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <cstring>

// Include the compiled VFS eBPF program
#include "vfs_monitor_enhanced_bytecode.h"

namespace ebpf {

VFSLayerMonitor::VFSLayerMonitor()
    : obj_(nullptr)
    , vfs_create_link_(nullptr)
    , vfs_mkdir_link_(nullptr)
    , vfs_unlink_link_(nullptr)
    , vfs_rmdir_link_(nullptr)
    , vfs_rename_link_(nullptr)
    , rb_(nullptr)
    , running_(false)
    , initialized_(false) {
}

VFSLayerMonitor::~VFSLayerMonitor() {
    stop();
    
    if (obj_) {
        bpf_object__close(obj_);
    }
}

bool VFSLayerMonitor::initialize() {
    if (initialized_) {
        return true;
    }

    if (!loadVFSProgram()) {
        printf("Failed to load VFS eBPF program\n");
        return false;
    }

    if (!attachKprobes()) {
        printf("Failed to attach VFS kprobes\n");
        return false;
    }

    // Set up ring buffer
    int map_fd = bpf_object__find_map_fd_by_name(obj_, "events");
    if (map_fd < 0) {
        printf("Failed to find events map\n");
        return false;
    }

    rb_ = ring_buffer__new(map_fd, handleRingBufferEvent, this, nullptr);
    if (!rb_) {
        printf("Failed to create ring buffer\n");
        return false;
    }

    initialized_ = true;
    printf("VFS Layer Monitor initialized successfully\n");
    return true;
}

bool VFSLayerMonitor::start() {
    if (!initialized_) {
        printf("VFS Layer Monitor not initialized\n");
        return false;
    }

    if (running_) {
        return true;
    }

    running_ = true;
    
    // Start ring buffer polling thread
    poll_thread_ = std::thread(&VFSLayerMonitor::ringBufferPollLoop, this);
    
    printf("VFS Layer Monitor started\n");
    return true;
}

void VFSLayerMonitor::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    
    if (poll_thread_.joinable()) {
        poll_thread_.join();
    }

    detachKprobes();
    
    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }

    printf("VFS Layer Monitor stopped\n");
}

void VFSLayerMonitor::setEventHandler(std::function<void(const vfs_event&)> handler) {
    event_handler_ = handler;
}

bool VFSLayerMonitor::loadVFSProgram() {
    struct bpf_object_open_opts opts = {};
    opts.sz = sizeof(struct bpf_object_open_opts);
    
    obj_ = bpf_object__open_mem(vfs_monitor_enhanced_o, vfs_monitor_enhanced_o_len, &opts);
    if (!obj_) {
        printf("Failed to open VFS eBPF object\n");
        return false;
    }

    int ret = bpf_object__load(obj_);
    if (ret) {
        printf("Failed to load VFS eBPF object: %d\n", ret);
        return false;
    }

    return true;
}

bool VFSLayerMonitor::attachKprobes() {
    struct bpf_program *prog;
    
    // Attach vfs_create kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_vfs_create");
    if (prog) {
        vfs_create_link_ = bpf_program__attach_kprobe(prog, false, "vfs_create");
        if (!vfs_create_link_) {
            printf("Failed to attach vfs_create kprobe\n");
            return false;
        }
    }
    
    // Attach vfs_mkdir kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_vfs_mkdir");
    if (prog) {
        vfs_mkdir_link_ = bpf_program__attach_kprobe(prog, false, "vfs_mkdir");
        if (!vfs_mkdir_link_) {
            printf("Failed to attach vfs_mkdir kprobe\n");
            return false;
        }
    }
    
    // Attach vfs_unlink kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_vfs_unlink");
    if (prog) {
        vfs_unlink_link_ = bpf_program__attach_kprobe(prog, false, "vfs_unlink");
        if (!vfs_unlink_link_) {
            printf("Failed to attach vfs_unlink kprobe\n");
            return false;
        }
    }
    
    // Attach vfs_rmdir kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_vfs_rmdir");
    if (prog) {
        vfs_rmdir_link_ = bpf_program__attach_kprobe(prog, false, "vfs_rmdir");
        if (!vfs_rmdir_link_) {
            printf("Failed to attach vfs_rmdir kprobe\n");
            return false;
        }
    }
    
    // Attach vfs_rename kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_vfs_rename");
    if (prog) {
        vfs_rename_link_ = bpf_program__attach_kprobe(prog, false, "vfs_rename");
        if (!vfs_rename_link_) {
            printf("Failed to attach vfs_rename kprobe\n");
            return false;
        }
    }
    
    printf("VFS kprobes attached successfully\n");
    return true;
}

void VFSLayerMonitor::detachKprobes() {
    if (vfs_create_link_) {
        bpf_link__destroy(vfs_create_link_);
        vfs_create_link_ = nullptr;
    }
    
    if (vfs_mkdir_link_) {
        bpf_link__destroy(vfs_mkdir_link_);
        vfs_mkdir_link_ = nullptr;
    }
    
    if (vfs_unlink_link_) {
        bpf_link__destroy(vfs_unlink_link_);
        vfs_unlink_link_ = nullptr;
    }
    
    if (vfs_rmdir_link_) {
        bpf_link__destroy(vfs_rmdir_link_);
        vfs_rmdir_link_ = nullptr;
    }
    
    if (vfs_rename_link_) {
        bpf_link__destroy(vfs_rename_link_);
        vfs_rename_link_ = nullptr;
    }
}

void VFSLayerMonitor::ringBufferPollLoop() {
    printf("VFS ring buffer polling started\n");
    
    while (running_) {
        int ret = ring_buffer__poll(rb_, 100); // 100ms timeout
        if (ret < 0 && ret != -EINTR) {
            printf("Ring buffer polling error: %d\n", ret);
            break;
        }
    }
    
    printf("VFS ring buffer polling stopped\n");
}

int VFSLayerMonitor::handleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
    VFSLayerMonitor *monitor = static_cast<VFSLayerMonitor*>(ctx);
    
    // Accept VFS events - handle both possible sizes due to struct packing differences
    if (data_sz == 4120 || data_sz == sizeof(vfs_event)) {
        struct vfs_event *event = static_cast<struct vfs_event*>(data);
        
        // Call the event handler if set
        if (monitor->event_handler_) {
            monitor->event_handler_(*event);
        }
        return 0;
    }
    
    // Debug: Log unexpected sizes occasionally for troubleshooting
    static int debug_counter = 0;
    if (++debug_counter % 1000 == 0) {
        printf("VFS Debug: Received %d events with size %zu (expected 4120)\n", 
               debug_counter, data_sz);
    }
    
    return 0;
}

} // namespace ebpf