// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "enhanced/enhanced_event_manager.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <spdlog/spdlog.h>

void printCapabilities(const ebpf::EnhancedEventManager::MonitoringCapabilities& caps) {
    std::cout << "\n=== 系统监控能力检测 ===" << std::endl;
    std::cout << "内核版本: " << caps.kernel_version_major << "." << caps.kernel_version_minor << std::endl;
    std::cout << "VFS kprobe支持: " << (caps.vfs_kprobe_available ? "✓" : "✗") << std::endl;
    std::cout << "VFS tracepoint支持: " << (caps.vfs_tracepoints_available ? "✓" : "✗") << std::endl;
    std::cout << "系统调用tracepoint支持: " << (caps.syscall_tracepoints_available ? "✓" : "✗") << std::endl;
    std::cout << "内存映射tracepoint支持: " << (caps.mm_tracepoints_available ? "✓" : "✗") << std::endl;
    std::cout << "CAP_BPF权限: " << (caps.has_cap_bpf ? "✓" : "✗") << std::endl;
    std::cout << "CAP_SYS_ADMIN权限: " << (caps.has_cap_sys_admin ? "✓" : "✗") << std::endl;
}

void printStrategy(ebpf::EnhancedEventManager::MonitoringStrategy strategy) {
    std::cout << "\n=== 选择的监控策略 ===" << std::endl;
    switch (strategy) {
        case ebpf::EnhancedEventManager::MonitoringStrategy::FULL_COVERAGE:
            std::cout << "策略: 完全覆盖 (VFS + 系统调用 + 内存映射)" << std::endl;
            break;
        case ebpf::EnhancedEventManager::MonitoringStrategy::VFS_SYSCALL:
            std::cout << "策略: VFS + 系统调用" << std::endl;
            break;
        case ebpf::EnhancedEventManager::MonitoringStrategy::SYSCALL_ONLY:
            std::cout << "策略: 仅系统调用" << std::endl;
            break;
        case ebpf::EnhancedEventManager::MonitoringStrategy::KERNEL_MODULE:
            std::cout << "策略: 内核模块回退" << std::endl;
            break;
    }
}

void printStats(const ebpf::EnhancedEventManager::MonitoringStats& stats) {
    std::cout << "\n=== 监控统计信息 ===" << std::endl;
    std::cout << "VFS事件捕获: " << stats.vfs_events_captured << std::endl;
    std::cout << "系统调用事件捕获: " << stats.syscall_events_captured << std::endl;
    std::cout << "内存映射事件捕获: " << stats.mmap_events_captured << std::endl;
    std::cout << "事件去重: " << stats.events_deduplicated << std::endl;
    std::cout << "事件合并: " << stats.events_merged << std::endl;
    std::cout << "事件发送: " << stats.events_sent << std::endl;
    std::cout << "CPU使用率: " << std::fixed << std::setprecision(2) << stats.cpu_usage_percent << "%" << std::endl;
    std::cout << "内存使用: " << stats.memory_usage_bytes << " bytes" << std::endl;
}

int main() {
    spdlog::set_level(spdlog::level::info);
    spdlog::info("启动增强版eBPF测试程序");

    // 创建增强版事件管理器
    ebpf::EnhancedEventManager manager;
    
    // 检测系统能力
    auto capabilities = manager.detectCapabilities();
    printCapabilities(capabilities);
    
    // 初始化管理器
    if (!manager.initialize()) {
        spdlog::error("初始化事件管理器失败");
        return 1;
    }
    
    auto strategy = manager.getActiveStrategy();
    printStrategy(strategy);
    
    // 事件计数器
    std::atomic<uint64_t> event_count{0};
    
    // 开始监控
    if (!manager.startMonitoring([&event_count](const struct vfs_event& event) {
        event_count++;
        spdlog::info("收到事件: action={}, path={}, pid={}", 
                    event.action, event.path, event.pid);
    })) {
        spdlog::error("启动监控失败");
        return 1;
    }

    spdlog::info("增强版eBPF监控已启动");
    spdlog::info("请创建、删除、重命名文件来测试事件捕获...");
    spdlog::info("按Ctrl+C停止测试");
    
    // 运行监控循环
    auto start_time = std::chrono::steady_clock::now();
    for (int i = 0; i < 60; i++) {  // 运行60秒
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
        
        if (i % 10 == 0) {  // 每10秒显示一次统计
            std::cout << "\n--- 运行时间: " << elapsed << "秒 ---" << std::endl;
            std::cout << "总事件数: " << event_count.load() << std::endl;
            
            auto stats = manager.getMonitoringStats();
            printStats(stats);
        }
    }

    // 停止监控
    manager.stopMonitoring();
    
    std::cout << "\n=== 测试完成 ===" << std::endl;
    std::cout << "总共处理事件: " << event_count.load() << std::endl;
    
    auto final_stats = manager.getMonitoringStats();
    printStats(final_stats);
    
    spdlog::info("增强版eBPF测试完成");
    return 0;
}