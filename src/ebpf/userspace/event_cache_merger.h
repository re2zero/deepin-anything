// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "../include/ebpf_common.h"
#include <vector>
#include <unordered_map>
#include <chrono>
#include <memory>

namespace ebpf {

class EventCacheMerger {
public:
    EventCacheMerger();
    ~EventCacheMerger();

    // Add event to cache for potential merging
    void addEvent(const struct vfs_event& event);
    
    // Flush expired events from cache
    std::vector<struct vfs_event> flushExpiredEvents();
    
    // Clear all cached events
    void clearCache();
    
    // Set cache window duration (default: 1000ms)
    void setWindowDuration(std::chrono::milliseconds duration);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ebpf 