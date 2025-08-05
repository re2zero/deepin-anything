// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "enhanced/simple_enhanced_manager.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <spdlog/spdlog.h>

void printCapabilities(const ebpf::SimpleEnhancedManager::MonitoringCapabilities& caps) {
    std::cout << "\n=== 系统监控能力检测 ===" << std::endl;
    std::cout << "内核版本: " << caps.kernel_version_major << "." << caps.kernel_version_minor << std::endl;
    std::cout << "系统调用tracepoint支持: " << (caps.syscall_tracepoints_available ? "✓" : "✗") << std::endl;
    std::cout << "权限检查: " << (caps.has_privileges ? "✓" : "✗") << std::endl;
}

void printStrategy(ebpf::SimpleEnhancedManager::MonitoringStrategy strategy) {
    std::cout << "\n=== 选择的监控策略 ===" << std::endl;
    switch (strategy) {
        case ebpf::SimpleEnhancedManager::MonitoringStrategy::SYSCALL_ONLY:
            std::cout << "策略: 仅系统调用" << std::endl;
            break;
        case ebpf::SimpleEnhancedManager::MonitoringStrategy::KERNEL_MODULE:
            std::cout << "策略: 内核模块回退" << std::endl;
            break;
    }
}

int main() {
    spdlog::set_level(spdlog::level::info);
    spdlog::info("启动简化版增强eBPF测试程序");

    // 创建简化版增强事件管理器
    ebpf::SimpleEnhancedManager manager;
    
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

    spdlog::info("简化版增强eBPF监控已启动");
    spdlog::info("请创建、删除、重命名文件来测试事件捕获...");
    spdlog::info("程序将运行30秒，按Ctrl+C可提前停止");
    
    // 运行监控循环
    auto start_time = std::chrono::steady_clock::now();
    for (int i = 0; i < 30; i++) {  // 运行30秒
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
        
        if (i % 5 == 0) {  // 每5秒显示一次统计
            std::cout << "\n--- 运行时间: " << elapsed << "秒 ---" << std::endl;
            std::cout << "总事件数: " << event_count.load() << std::endl;
        }
    }

    // 停止监控
    manager.stopMonitoring();
    
    std::cout << "\n=== 测试完成 ===" << std::endl;
    std::cout << "总共处理事件: " << event_count.load() << std::endl;
    
    spdlog::info("简化版增强eBPF测试完成");
    return 0;
}