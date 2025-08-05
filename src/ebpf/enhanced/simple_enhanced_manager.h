// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "../include/event_manager.h"
#include <string>

namespace ebpf {

class SimpleEnhancedManager : public EventManager {
public:
    enum class MonitoringStrategy {
        SYSCALL_ONLY,       // 仅系统调用
        KERNEL_MODULE       // 回退到内核模块
    };
    
    struct MonitoringCapabilities {
        bool syscall_tracepoints_available{false};
        int kernel_version_major{0};
        int kernel_version_minor{0};
        bool has_privileges{false};
    };

    SimpleEnhancedManager();
    ~SimpleEnhancedManager();

    // Enhanced methods (not overriding, but providing enhanced functionality)
    bool initialize();
    bool startMonitoring(EventCallback callback);
    void stopMonitoring();
    EventSourceType getActiveSource() const;

    // Enhanced functionality
    MonitoringStrategy getActiveStrategy() const;
    MonitoringCapabilities detectCapabilities();
    
private:
    MonitoringStrategy strategy_;
    MonitoringCapabilities capabilities_;
    
    MonitoringStrategy selectOptimalStrategy(const MonitoringCapabilities& caps);
    bool initializeSyscallOnly();
    bool initializeKernelModule();
};

} // namespace ebpf