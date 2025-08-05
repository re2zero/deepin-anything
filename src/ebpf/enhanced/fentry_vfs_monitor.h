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
extern unsigned char fentry_vfs_monitor_o[];
extern unsigned int fentry_vfs_monitor_o_len;

namespace ebpf {

class FentryVFSMonitor {
public:
    FentryVFSMonitor() : obj_(nullptr), ring_buf_(nullptr), is_running_(false) {}
    ~FentryVFSMonitor();

    // Initialize the fentry VFS monitor
    bool initialize();
    
    // Start monitoring VFS layer events using fentry
    bool start();
    
    // Stop monitoring
    void stop();
    
    // Set event handler callback
    void setEventHandler(std::function<void(const vfs_event&)> handler);

private:
    // eBPF object and links
    struct bpf_object *obj_;
    std::vector<struct bpf_link*> fentry_links_;
    
    // Ring buffer for events
    struct ring_buffer *ring_buf_;
    
    // Event handler
    std::function<void(const vfs_event&)> event_handler_;
    
    // Polling thread
    std::thread polling_thread_;
    std::atomic<bool> is_running_;
    
    // Internal methods
    bool loadFentryProgram();
    bool attachFentryHooks();
    void detachFentryHooks();
    void ringBufferPollLoop();
    
    // Ring buffer callback
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz);
};

} // namespace ebpf 