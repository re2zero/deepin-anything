// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "simple_enhanced_manager.h"
#include <sys/utsname.h>
#include <unistd.h>
#include <cstdlib>
#include <spdlog/spdlog.h>

namespace ebpf {

SimpleEnhancedManager::SimpleEnhancedManager() 
    : strategy_(MonitoringStrategy::KERNEL_MODULE) {}

SimpleEnhancedManager::~SimpleEnhancedManager() {
    stopMonitoring();
}

bool SimpleEnhancedManager::initialize() {
    capabilities_ = detectCapabilities();
    strategy_ = selectOptimalStrategy(capabilities_);
    
    spdlog::info("检测到的监控能力:");
    spdlog::info("  系统调用tracepoint支持: {}", capabilities_.syscall_tracepoints_available);
    spdlog::info("  内核版本: {}.{}", capabilities_.kernel_version_major, capabilities_.kernel_version_minor);
    spdlog::info("  权限检查: {}", capabilities_.has_privileges);
    
    switch (strategy_) {
        case MonitoringStrategy::SYSCALL_ONLY:
            spdlog::info("选择策略: 仅系统调用");
            return initializeSyscallOnly();
        case MonitoringStrategy::KERNEL_MODULE:
            spdlog::info("选择策略: 内核模块回退");
            return initializeKernelModule();
    }
    
    return false;
}

bool SimpleEnhancedManager::startMonitoring(EventCallback callback) {
    if (strategy_ == MonitoringStrategy::KERNEL_MODULE) {
        // 使用基类的实现
        return EventManager::startMonitoring(callback);
    } else {
        // 使用eBPF实现
        return EventManager::startMonitoring(callback);
    }
}

void SimpleEnhancedManager::stopMonitoring() {
    EventManager::stopMonitoring();
}

EventManager::EventSourceType SimpleEnhancedManager::getActiveSource() const {
    return (strategy_ == MonitoringStrategy::KERNEL_MODULE) ? 
           EventSourceType::KERNEL_MODULE_SOURCE : EventSourceType::EBPF_SOURCE;
}

SimpleEnhancedManager::MonitoringStrategy SimpleEnhancedManager::getActiveStrategy() const {
    return strategy_;
}

SimpleEnhancedManager::MonitoringCapabilities SimpleEnhancedManager::detectCapabilities() {
    MonitoringCapabilities caps;
    
    // 检测内核版本
    struct utsname uts;
    if (uname(&uts) == 0) {
        sscanf(uts.release, "%d.%d", &caps.kernel_version_major, &caps.kernel_version_minor);
    }
    
    // 检查eBPF支持 (内核 >= 4.4)
    bool ebpf_supported = (caps.kernel_version_major > 4) || 
                         (caps.kernel_version_major == 4 && caps.kernel_version_minor >= 4);
    
    if (!ebpf_supported) {
        return caps;
    }
    
    // 检查权限 (简化版本，只检查是否为root)
    caps.has_privileges = (geteuid() == 0);
    
    if (!caps.has_privileges) {
        spdlog::warn("需要root权限来使用eBPF");
        return caps;
    }
    
    // 假设系统调用tracepoint可用
    caps.syscall_tracepoints_available = ebpf_supported;
    
    return caps;
}

SimpleEnhancedManager::MonitoringStrategy SimpleEnhancedManager::selectOptimalStrategy(const MonitoringCapabilities& caps) {
    // 如果没有eBPF支持或权限，使用内核模块
    if (!caps.has_privileges || !caps.syscall_tracepoints_available) {
        return MonitoringStrategy::KERNEL_MODULE;
    }
    
    // 使用系统调用监控
    return MonitoringStrategy::SYSCALL_ONLY;
}

bool SimpleEnhancedManager::initializeSyscallOnly() {
    try {
        // 使用基类的eBPF初始化
        return EventManager::initialize();
    } catch (const std::exception& e) {
        spdlog::error("初始化系统调用监控失败: {}", e.what());
        return false;
    }
}

bool SimpleEnhancedManager::initializeKernelModule() {
    // 尝试加载内核模块
    int ret = system("modprobe vfs_monitor 2>/dev/null");
    if (ret == 0) {
        spdlog::info("内核模块加载成功");
        return EventManager::initialize();
    }
    
    spdlog::error("内核模块加载失败");
    return false;
}

} // namespace ebpf