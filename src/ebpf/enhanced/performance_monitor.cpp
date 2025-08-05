// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "performance_monitor.h"
#include <iostream>
#include <iomanip>

namespace ebpf {

PerformanceMonitor::PerformanceMonitor() 
    : monitoring_(false) {
}

PerformanceMonitor::~PerformanceMonitor() {
    stop();
}

void PerformanceMonitor::start() {
    if (monitoring_) {
        return;
    }
    
    monitoring_ = true;
    stats_.start_time = std::chrono::steady_clock::now();
    stats_.last_report_time = stats_.start_time;
    last_periodic_report_ = stats_.start_time;
    
    // Reset all counters
    stats_.total_events = 0;
    stats_.vfs_events = 0;
    stats_.syscall_events = 0;
    stats_.mmap_events = 0;
    stats_.duplicate_events = 0;
    stats_.processed_events = 0;
}

void PerformanceMonitor::stop() {
    monitoring_ = false;
}

void PerformanceMonitor::recordEvent(const std::string& source_type) {
    if (!monitoring_) {
        return;
    }
    
    stats_.total_events++;
    
    if (source_type == "VFS") {
        stats_.vfs_events++;
    } else if (source_type == "SYSCALL") {
        stats_.syscall_events++;
    } else if (source_type == "MMAP") {
        stats_.mmap_events++;
    }
}

void PerformanceMonitor::recordDuplicate() {
    if (monitoring_) {
        stats_.duplicate_events++;
    }
}

void PerformanceMonitor::recordProcessed() {
    if (monitoring_) {
        stats_.processed_events++;
    }
}

void PerformanceMonitor::printStats() {
    if (!monitoring_) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
    
    std::cout << "\n=== Performance Statistics ===\n";
    std::cout << "Runtime: " << duration.count() << " seconds\n";
    std::cout << "Total Events: " << stats_.total_events.load() << "\n";
    std::cout << "  - VFS Events: " << stats_.vfs_events.load() << "\n";
    std::cout << "  - Syscall Events: " << stats_.syscall_events.load() << "\n";
    std::cout << "  - MMap Events: " << stats_.mmap_events.load() << "\n";
    std::cout << "Duplicate Events: " << stats_.duplicate_events.load() << "\n";
    std::cout << "Processed Events: " << stats_.processed_events.load() << "\n";
    
    if (duration.count() > 0) {
        double eps = static_cast<double>(stats_.total_events.load()) / duration.count();
        std::cout << "Events/Second: " << std::fixed << std::setprecision(2) << eps << "\n";
    }
    
    if (stats_.total_events.load() > 0) {
        double dup_rate = static_cast<double>(stats_.duplicate_events.load()) / stats_.total_events.load() * 100.0;
        std::cout << "Duplication Rate: " << std::fixed << std::setprecision(2) << dup_rate << "%\n";
    }
    
    std::cout << "==============================\n";
}

void PerformanceMonitor::printPeriodicStats() {
    auto now = std::chrono::steady_clock::now();
    auto duration_since_last = std::chrono::duration_cast<std::chrono::seconds>(now - last_periodic_report_);
    
    // Print stats every 5 seconds
    if (duration_since_last.count() >= 5) {
        auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
        
        std::cout << "[" << total_duration.count() << "s] ";
        std::cout << "Events: " << stats_.total_events.load();
        std::cout << " (VFS:" << stats_.vfs_events.load();
        std::cout << " SYS:" << stats_.syscall_events.load();
        std::cout << " MMP:" << stats_.mmap_events.load() << ")";
        
        if (total_duration.count() > 0) {
            double eps = static_cast<double>(stats_.total_events.load()) / total_duration.count();
            std::cout << " Rate:" << std::fixed << std::setprecision(1) << eps << "/s";
        }
        
        std::cout << std::endl;
        
        last_periodic_report_ = now;
    }
}

double PerformanceMonitor::getEventsPerSecond() const {
    if (!monitoring_) {
        return 0.0;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
    
    if (duration.count() > 0) {
        return static_cast<double>(stats_.total_events.load()) / duration.count();
    }
    
    return 0.0;
}

double PerformanceMonitor::getDuplicationRate() const {
    if (stats_.total_events.load() > 0) {
        return static_cast<double>(stats_.duplicate_events.load()) / stats_.total_events.load() * 100.0;
    }
    return 0.0;
}

uint64_t PerformanceMonitor::getTotalEvents() const {
    return stats_.total_events.load();
}

} // namespace ebpf 