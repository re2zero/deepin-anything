// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <iostream>
#include <chrono>
#include <thread>

#include "enhanced/enhanced_event_manager.h"

using namespace ebpf;

void printCapabilities(const EnhancedEventManager::MonitoringCapabilities& caps) {
    std::cout << "=== System Capabilities ===" << std::endl;
    std::cout << "Kernel Version: " << caps.kernel_version_major << "." << caps.kernel_version_minor << std::endl;
    std::cout << "VFS Tracepoints: " << (caps.vfs_tracepoints_available ? "Available" : "Not Available") << std::endl;
    std::cout << "VFS Kprobe: " << (caps.vfs_kprobe_available ? "Available" : "Not Available") << std::endl;
    std::cout << "MM Tracepoints: " << (caps.mm_tracepoints_available ? "Available" : "Not Available") << std::endl;
    std::cout << "Syscall Tracepoints: " << (caps.syscall_tracepoints_available ? "Available" : "Not Available") << std::endl;
    std::cout << "CAP_BPF: " << (caps.has_cap_bpf ? "Yes" : "No") << std::endl;
    std::cout << "CAP_SYS_ADMIN: " << (caps.has_cap_sys_admin ? "Yes" : "No") << std::endl;
    std::cout << std::endl;
}

void printStrategy(EnhancedEventManager::MonitoringStrategy strategy) {
    std::cout << "=== Selected Strategy ===" << std::endl;
    switch (strategy) {
        case EnhancedEventManager::FULL_COVERAGE:
            std::cout << "Strategy: FULL_COVERAGE (VFS + Syscall + MMap)" << std::endl;
            break;
        case EnhancedEventManager::SYSCALL_ONLY:
            std::cout << "Strategy: SYSCALL_ONLY (Syscall tracepoints only)" << std::endl;
            break;
        case EnhancedEventManager::KERNEL_MODULE:
            std::cout << "Strategy: KERNEL_MODULE (Fallback to kernel module)" << std::endl;
            break;
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "Enhanced Event Manager Test" << std::endl;
    std::cout << "===========================" << std::endl;

    // Create enhanced event manager
    EnhancedEventManager manager;

    // Initialize first (this will detect capabilities and select strategy)
    std::cout << "Initializing Enhanced Event Manager..." << std::endl;
    if (!manager.initialize()) {
        std::cerr << "Failed to initialize Enhanced Event Manager" << std::endl;
        return 1;
    }

    // Get capabilities and strategy after initialization
    auto caps = manager.getCapabilities();
    printCapabilities(caps);
    
    auto strategy = manager.getCurrentStrategy();
    printStrategy(strategy);

    // Set up event handler
    int event_count = 0;
    manager.setEventHandler([&event_count](const vfs_event& event) {
        event_count++;
        std::cout << "Event #" << event_count << ": action=" << static_cast<int>(event.action) 
                  << ", path=" << event.path << ", pid=" << event.pid << std::endl;
    });

    std::cout << "Initialization successful!" << std::endl;

    // Start monitoring
    std::cout << "Starting monitoring..." << std::endl;
    if (!manager.startMonitoring()) {
        std::cerr << "Failed to start monitoring" << std::endl;
        return 1;
    }
    std::cout << "Monitoring started!" << std::endl;

    // Run for a few seconds to test
    std::cout << "Running for 10 seconds... (create some files to test)" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // Stop monitoring
    std::cout << "Stopping monitoring..." << std::endl;
    manager.stopMonitoring();
    
    std::cout << "Test completed. Total events received: " << event_count << std::endl;
    
    return 0;
}