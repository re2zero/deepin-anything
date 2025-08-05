// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>
#include <functional>
#include "ebpf_common.h"

namespace ebpf {

class EventManager {
public:
    enum class EventSourceType {
        EBPF_SOURCE,
        KERNEL_MODULE_SOURCE
    };

    using EventCallback = std::function<void(const struct vfs_event&)>;

    EventManager();
    ~EventManager();

    // Initialize and select appropriate event source
    bool initialize();
    
    // Start monitoring file system events
    bool startMonitoring(EventCallback callback);
    
    // Stop monitoring
    void stopMonitoring();
    
    // Get active event source type
    EventSourceType getActiveSource() const;
    
    // Check if eBPF is supported on this system
    static bool isEBPFSupported();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ebpf 