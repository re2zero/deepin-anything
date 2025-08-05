// SPDX-License-Identifier: GPL-3.0-or-later

#include "fexit_production_monitor.h"
#include <iostream>
#include <chrono>
#include <cstring>

// 包含生成的eBPF字节码
#include "fexit_filesystem_monitor_bytecode.h"

namespace ebpf {

// VFS层fexit程序名称
const std::vector<const char*> FexitProductionMonitor::VFS_FEXIT_PROGRAMS = {
    "fexit_vfs_create",
    "fexit_vfs_mkdir", 
    "fexit_vfs_unlink",
    "fexit_vfs_rmdir",
    "fexit_vfs_rename"
};

// Syscall层fexit程序名称（关键路径获取）
const std::vector<const char*> FexitProductionMonitor::SYSCALL_FEXIT_PROGRAMS = {
    "fexit_sys_openat2",
    "fexit_sys_open"
};

FexitProductionMonitor::FexitProductionMonitor() 
    : obj_(nullptr), ring_buf_(nullptr), is_monitoring_(false) {
}

FexitProductionMonitor::~FexitProductionMonitor() {
    cleanup();
}

bool FexitProductionMonitor::initialize() {
    std::cout << "🚀 Initializing Fexit Production Monitor..." << std::endl;
    
    // 首先检查fexit支持能力
    capabilities_ = checkFexitCapabilities();
    
    if (!capabilities_.supports_fexit) {
        std::cerr << "❌ System does not support fexit (kernel 5.5+ required)" << std::endl;
        return false;
    }
    
    // 加载eBPF程序
    if (!loadFexitProgram()) {
        std::cerr << "❌ Failed to load fexit eBPF program" << std::endl;
        return false;
    }
    
    // 附加fexit程序
    if (!attachFexitPrograms()) {
        std::cerr << "❌ Failed to attach fexit programs" << std::endl;
        return false;
    }
    
    // 设置Ring Buffer
    if (!setupRingBuffer()) {
        std::cerr << "❌ Failed to setup ring buffer" << std::endl;
        return false;
    }
    
    std::cout << "✅ Fexit Production Monitor initialized successfully" << std::endl;
    std::cout << "📊 VFS hooks: " << capabilities_.attached_vfs_programs 
              << ", Syscall hooks: " << capabilities_.attached_syscall_programs << std::endl;
    
    return true;
}

FexitProductionMonitor::FexitCapabilities FexitProductionMonitor::checkFexitCapabilities() {
    FexitCapabilities caps;
    
    // 检查内核版本是否支持fexit (5.5+)
    // 简化检查：如果能加载测试程序就认为支持
    caps.supports_fexit = true;  // 将在实际加载时验证
    caps.supports_vfs_hooks = true;
    caps.supports_syscall_hooks = true;
    
    return caps;
}

bool FexitProductionMonitor::loadFexitProgram() {
    struct bpf_object_open_opts opts = {};
    opts.sz = sizeof(struct bpf_object_open_opts);
    
    obj_ = bpf_object__open_mem(fexit_filesystem_monitor_o, fexit_filesystem_monitor_o_len, &opts);
    if (!obj_) {
        std::cerr << "❌ Failed to open fexit eBPF object" << std::endl;
        return false;
    }
    
    // 加载程序到内核
    if (bpf_object__load(obj_) != 0) {
        std::cerr << "❌ Failed to load fexit eBPF program into kernel" << std::endl;
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }
    
    std::cout << "✅ Fexit eBPF program loaded successfully" << std::endl;
    return true;
}

bool FexitProductionMonitor::attachFexitPrograms() {
    std::cout << "🔗 Attaching fexit programs..." << std::endl;
    
    capabilities_.attached_vfs_programs = 0;
    capabilities_.attached_syscall_programs = 0;
    
    // 附加VFS层fexit程序
    for (const char* prog_name : VFS_FEXIT_PROGRAMS) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj_, prog_name);
        if (prog) {
            struct bpf_link *link = bpf_program__attach(prog);
            if (link) {
                fexit_links_.push_back(link);
                capabilities_.attached_vfs_programs++;
                std::cout << "✅ Attached VFS fexit: " << prog_name << std::endl;
            } else {
                std::cout << "⚠️ Failed to attach VFS fexit: " << prog_name << std::endl;
            }
        } else {
            std::cout << "⚠️ VFS program not found: " << prog_name << std::endl;
        }
    }
    
    // 附加Syscall层fexit程序（关键路径获取）
    for (const char* prog_name : SYSCALL_FEXIT_PROGRAMS) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj_, prog_name);
        if (prog) {
            struct bpf_link *link = bpf_program__attach(prog);
            if (link) {
                fexit_links_.push_back(link);
                capabilities_.attached_syscall_programs++;
                std::cout << "✅ Attached Syscall fexit: " << prog_name << std::endl;
            } else {
                std::cout << "⚠️ Failed to attach Syscall fexit: " << prog_name << std::endl;
            }
        } else {
            std::cout << "⚠️ Syscall program not found: " << prog_name << std::endl;
        }
    }
    
    capabilities_.total_attached = capabilities_.attached_vfs_programs + 
                                  capabilities_.attached_syscall_programs;
    
    std::cout << "📊 Total attached fexit programs: " << capabilities_.total_attached 
              << " (VFS: " << capabilities_.attached_vfs_programs 
              << ", Syscall: " << capabilities_.attached_syscall_programs << ")" << std::endl;
    
    return capabilities_.total_attached > 0;
}

bool FexitProductionMonitor::setupRingBuffer() {
    struct bpf_map *map = bpf_object__find_map_by_name(obj_, "fexit_fs_events");
    if (!map) {
        std::cerr << "❌ Failed to find fexit ring buffer map" << std::endl;
        return false;
    }
    
    ring_buf_ = ring_buffer__new(bpf_map__fd(map), handleRingBufferEvent, this, nullptr);
    if (!ring_buf_) {
        std::cerr << "❌ Failed to create fexit ring buffer" << std::endl;
        return false;
    }
    
    std::cout << "✅ Fexit ring buffer setup successful" << std::endl;
    return true;
}

bool FexitProductionMonitor::startMonitoring(EventHandler handler) {
    if (is_monitoring_.load()) {
        std::cout << "⚠️ Fexit monitor is already running" << std::endl;
        return false;
    }
    
    event_handler_ = handler;
    is_monitoring_ = true;
    
    // 启动轮询线程
    polling_thread_ = std::thread(&FexitProductionMonitor::pollRingBuffer, this);
    
    std::cout << "🎯 Fexit Production Monitor started" << std::endl;
    std::cout << "特点：只记录成功操作 + 完整路径 + 高性能" << std::endl;
    
    return true;
}

void FexitProductionMonitor::stopMonitoring() {
    if (!is_monitoring_.load()) {
        return;
    }
    
    is_monitoring_ = false;
    
    if (polling_thread_.joinable()) {
        polling_thread_.join();
    }
    
    std::cout << "🛑 Fexit Production Monitor stopped" << std::endl;
}

void FexitProductionMonitor::pollRingBuffer() {
    auto last_update = std::chrono::steady_clock::now();
    uint64_t last_total_events = 0;
    
    while (is_monitoring_.load()) {
        ring_buffer__poll(ring_buf_, 100);
        
        // 每秒更新一次性能统计
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_update);
        if (elapsed.count() >= 1) {
            uint64_t current_total = stats_.total_events.load();
            stats_.events_per_second = current_total - last_total_events;
            last_total_events = current_total;
            last_update = now;
        }
    }
}

int FexitProductionMonitor::handleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
    auto *monitor = static_cast<FexitProductionMonitor*>(ctx);
    
    if (data_sz == sizeof(vfs_event) || data_sz == 4120) {
        const vfs_event *event = static_cast<const vfs_event*>(data);
        
        // 更新统计信息
        monitor->stats_.total_events++;
        
        switch(event->source_type) {
            case VFS_SOURCE:
                monitor->stats_.vfs_events++;
                break;
            case SYSCALL_SOURCE:
                monitor->stats_.syscall_events++;
                if (event->cookie == 1) {  // 有路径的事件
                    monitor->stats_.path_events++;
                }
                break;
        }
        
        // 调用事件处理器
        if (monitor->event_handler_) {
            monitor->event_handler_(event);
        }
    }
    
    return 0;
}

void FexitProductionMonitor::cleanup() {
    stopMonitoring();
    
    if (ring_buf_) {
        ring_buffer__free(ring_buf_);
        ring_buf_ = nullptr;
    }
    
    for (auto link : fexit_links_) {
        bpf_link__destroy(link);
    }
    fexit_links_.clear();
    
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
}

} // namespace ebpf 