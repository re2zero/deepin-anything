// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENHANCED_EVENT_MANAGER_H
#define ENHANCED_EVENT_MANAGER_H

#include <memory>
#include <functional>
#include <sys/utsname.h>

#include "event_manager.h"

namespace ebpf {

class VFSLayerMonitor;
class MemoryMapMonitor;
class EventDeduplicator;
class PerformanceMonitor;

class EnhancedEventManager {
public:
    enum MonitoringStrategy {
        FULL_COVERAGE,      // VFS + Syscall + MMap
        SYSCALL_ONLY,       // 仅系统调用
        KERNEL_MODULE       // 回退到内核模块
    };
    
    struct MonitoringCapabilities {
        bool vfs_tracepoints_available;
        bool vfs_kprobe_available;
        bool mm_tracepoints_available;
        bool syscall_tracepoints_available;
        int kernel_version_major;
        int kernel_version_minor;
        bool has_cap_bpf;
        bool has_cap_sys_admin;
    };

    EnhancedEventManager();
    ~EnhancedEventManager();

    bool initialize();
    MonitoringStrategy selectOptimalStrategy();
    MonitoringCapabilities detectCapabilities();
    
    bool startMonitoring();
    void stopMonitoring();
    
    void setEventHandler(std::function<void(const vfs_event&)> handler);
    
    // Performance monitoring
    void printPerformanceStats() const;
    double getEventsPerSecond() const;
    
    MonitoringStrategy getCurrentStrategy() const { return current_strategy_; }
    const MonitoringCapabilities& getCapabilities() const { return capabilities_; }

private:
    bool initializeFullCoverage();
    bool initializeSyscallOnly();
    bool initializeKernelModule();
    
    bool checkVFSTracepointsAvailable();
    bool checkVFSKprobeAvailable();
    bool checkMMTracepointsAvailable();
    bool checkSyscallTracepointsAvailable();
    bool checkCapabilities();
    int parseKernelVersion();

private:
    MonitoringStrategy current_strategy_;
    MonitoringCapabilities capabilities_;
    
    std::unique_ptr<VFSLayerMonitor> vfs_monitor_;
    std::unique_ptr<MemoryMapMonitor> mmap_monitor_;
    std::unique_ptr<EventManager> syscall_monitor_;
    std::unique_ptr<EventDeduplicator> deduplicator_;
    std::unique_ptr<PerformanceMonitor> perf_monitor_;
    
    std::function<void(const vfs_event&)> event_handler_;
    bool initialized_;
    bool monitoring_;
};

} // namespace ebpf

#endif // ENHANCED_EVENT_MANAGER_H