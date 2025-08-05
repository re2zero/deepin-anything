// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "memory_map_monitor.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <cstring>

// Include the compiled MMap eBPF program 
#include "mmap_monitor_bytecode.h"

namespace ebpf {

MemoryMapMonitor::MemoryMapMonitor()
    : obj_(nullptr)
    , mmap_link_(nullptr)
    , munmap_link_(nullptr)
    , msync_link_(nullptr)
    , openat_link_(nullptr)
    , rb_(nullptr)
    , running_(false)
    , initialized_(false) {
}

MemoryMapMonitor::~MemoryMapMonitor() {
    stop();
    
    // Detach all kprobes
    detachTracepoints();
    
    if (obj_) {
        bpf_object__close(obj_);
    }
}

bool MemoryMapMonitor::initialize() {
    if (initialized_) {
        return true;
    }

    printf("Memory Map Monitor: Initializing mmap eBPF monitoring...\n");
    
    if (!loadMMapProgram()) {
        printf("Memory Map Monitor: Failed to load eBPF program\n");
        return false;
    }
    
    if (!attachTracepoints()) {
        printf("Memory Map Monitor: Failed to attach kprobes\n");
        return false;
    }
    
    printf("Memory Map Monitor: Initialization successful\n");
    initialized_ = true;
    return true;
}

bool MemoryMapMonitor::start() {
    if (!initialized_) {
        printf("Memory Map Monitor not initialized\n");
        return false;
    }

    if (running_) {
        return true;
    }

    // Set up ring buffer for mmap events
    int map_fd = bpf_object__find_map_fd_by_name(obj_, "mmap_events");
    if (map_fd < 0) {
        printf("Memory Map Monitor: Failed to find mmap_events map\n");
        return false;
    }

    rb_ = ring_buffer__new(map_fd, handleRingBufferEvent, this, nullptr);
    if (!rb_) {
        printf("Memory Map Monitor: Failed to create ring buffer\n");
        return false;
    }

    running_ = true;
    
    // Start polling thread
    poll_thread_ = std::thread(&MemoryMapMonitor::ringBufferPollLoop, this);
    
    printf("Memory Map Monitor: Started successfully\n");
    return true;
}

void MemoryMapMonitor::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    
    // Stop polling thread
    if (poll_thread_.joinable()) {
        poll_thread_.join();
    }
    
    // Cleanup ring buffer
    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }
    
    printf("Memory Map Monitor stopped\n");
}

void MemoryMapMonitor::setEventHandler(std::function<void(const vfs_event&)> handler) {
    event_handler_ = handler;
}

bool MemoryMapMonitor::loadMMapProgram() {
    struct bpf_object_open_opts opts = {};
    opts.sz = sizeof(struct bpf_object_open_opts);
    
    obj_ = bpf_object__open_mem(mmap_monitor_o, mmap_monitor_o_len, &opts);
    if (!obj_) {
        printf("Failed to open MMap eBPF object\n");
        return false;
    }

    int ret = bpf_object__load(obj_);
    if (ret) {
        printf("Failed to load MMap eBPF object: %d\n", ret);
        return false;
    }

    return true;
}

bool MemoryMapMonitor::attachTracepoints() {
    struct bpf_program *prog;
    
    // Attach mmap kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_mmap");
    if (prog) {
        mmap_link_ = bpf_program__attach_kprobe(prog, false, "sys_mmap");
        if (!mmap_link_) {
            printf("Warning: Failed to attach mmap kprobe (may not be available)\n");
        }
    }
    
    // Attach munmap kprobe  
    prog = bpf_object__find_program_by_name(obj_, "trace_munmap");
    if (prog) {
        munmap_link_ = bpf_program__attach_kprobe(prog, false, "sys_munmap");
        if (!munmap_link_) {
            printf("Warning: Failed to attach munmap kprobe (may not be available)\n");
        }
    }
    
    // Attach msync kprobe
    prog = bpf_object__find_program_by_name(obj_, "trace_msync");
    if (prog) {
        msync_link_ = bpf_program__attach_kprobe(prog, false, "sys_msync");
        if (!msync_link_) {
            printf("Warning: Failed to attach msync kprobe (may not be available)\n");
        }
    }
    
    // Return true even if some attachments failed (mmap monitoring is optional)
    printf("Memory Map Monitor: Kprobe attachment completed (some may have failed)\n");
    return true;
}

void MemoryMapMonitor::detachTracepoints() {
    if (mmap_link_) {
        bpf_link__destroy(mmap_link_);
        mmap_link_ = nullptr;
    }
    
    if (munmap_link_) {
        bpf_link__destroy(munmap_link_);
        munmap_link_ = nullptr;
    }
    
    if (msync_link_) {
        bpf_link__destroy(msync_link_);
        msync_link_ = nullptr;
    }
    
    if (openat_link_) {
        bpf_link__destroy(openat_link_);
        openat_link_ = nullptr;
    }
}

void MemoryMapMonitor::ringBufferPollLoop() {
    printf("Memory Map Monitor: Ring buffer polling started\n");
    
    while (running_) {
        if (rb_) {
            int ret = ring_buffer__poll(rb_, 100); // 100ms timeout
            if (ret < 0 && ret != -EINTR) {
                printf("Memory Map Monitor: Ring buffer polling error: %d\n", ret);
                break;
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    printf("Memory Map Monitor: Ring buffer polling stopped\n");
}

int MemoryMapMonitor::handleRingBufferEvent(void* ctx, void* data, size_t data_sz) {
    MemoryMapMonitor *monitor = static_cast<MemoryMapMonitor*>(ctx);
    
    // Accept mmap events (should be same size as vfs_event since we use the same struct)
    if (data_sz == sizeof(vfs_event) || data_sz == 4120) {
        struct vfs_event *event = static_cast<struct vfs_event*>(data);
        
        // Call the event handler if set
        if (monitor->event_handler_) {
            monitor->event_handler_(*event);
        }
        return 0;
    }
    
    // Debug: Log unexpected sizes occasionally
    static int debug_counter = 0;
    if (++debug_counter % 500 == 0) {
        printf("MMap Debug: Received %d events with size %zu (expected %zu or 4120)\n", 
               debug_counter, data_sz, sizeof(vfs_event));
    }
    
    return 0;
}

} // namespace ebpf 