// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "include/event_manager.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <spdlog/spdlog.h>

int main() {
    spdlog::set_level(spdlog::level::debug);
    spdlog::info("Starting eBPF test program");

    // Check eBPF support
    if (ebpf::EventManager::isEBPFSupported()) {
        spdlog::info("✓ eBPF is supported on this system");
    } else {
        spdlog::warn("✗ eBPF is not supported on this system");
    }

    // Create event manager
    ebpf::EventManager manager;
    
    if (!manager.initialize()) {
        spdlog::error("Failed to initialize event manager");
        return 1;
    }

    spdlog::info("Event manager initialized successfully");
    spdlog::info("Active event source: {}", 
                manager.getActiveSource() == ebpf::EventManager::EventSourceType::EBPF_SOURCE 
                ? "eBPF" : "Kernel Module");

    // Start monitoring
    if (!manager.startMonitoring([](const struct vfs_event& event) {
        spdlog::info("Received event: action={}, path={}", event.action, event.path);
    })) {
        spdlog::error("Failed to start monitoring");
        return 1;
    }

    spdlog::info("Event monitoring started. Test by creating/deleting files...");
    spdlog::info("Press Ctrl+C to stop");

    // Run for 30 seconds or until interrupted
    for (int i = 0; i < 30; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (i % 5 == 0) {
            spdlog::info("Running... {}s", i);
        }
    }

    manager.stopMonitoring();
    spdlog::info("Test completed");
    return 0;
} 