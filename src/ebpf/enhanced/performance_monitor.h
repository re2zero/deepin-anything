// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PERFORMANCE_MONITOR_H
#define PERFORMANCE_MONITOR_H

#include <chrono>
#include <unordered_map>
#include <string>
#include <atomic>

namespace ebpf {

struct PerformanceStats {
    std::atomic<uint64_t> total_events{0};
    std::atomic<uint64_t> vfs_events{0};
    std::atomic<uint64_t> syscall_events{0};
    std::atomic<uint64_t> mmap_events{0};
    std::atomic<uint64_t> duplicate_events{0};
    std::atomic<uint64_t> processed_events{0};
    
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_report_time;
};

class PerformanceMonitor {
public:
    PerformanceMonitor();
    ~PerformanceMonitor();

    void start();
    void stop();
    
    void recordEvent(const std::string& source_type);
    void recordDuplicate();
    void recordProcessed();
    
    void printStats();
    void printPeriodicStats();
    
    // Performance metrics
    double getEventsPerSecond() const;
    double getDuplicationRate() const;
    uint64_t getTotalEvents() const;

private:
    PerformanceStats stats_;
    bool monitoring_;
    std::chrono::steady_clock::time_point last_periodic_report_;
};

} // namespace ebpf

#endif // PERFORMANCE_MONITOR_H 