// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../include/event_manager.h"
#include "../include/ebpf_common.h"
#include "ebpf_program_loader.h"
#include "event_cache_merger.h"
#include "netlink_sender.h"

#include <unistd.h>
#include <sys/utsname.h>
#include <fstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>

namespace ebpf {

class EventManager::Impl {
public:
    Impl() : source_type_(EventSourceType::KERNEL_MODULE_SOURCE),
             monitoring_(false) {}

    bool initialize() {
        if (isEBPFSupported() && initializeEBPFSource()) {
            source_type_ = EventSourceType::EBPF_SOURCE;
            spdlog::info("Using eBPF event source for file monitoring");
            return true;
        }

        spdlog::warn("eBPF not available, falling back to kernel module");
        return initializeKernelModule();
    }

    bool startMonitoring(EventCallback callback) {
        if (monitoring_) {
            return false;
        }

        event_callback_ = callback;
        monitoring_ = true;

        if (source_type_ == EventSourceType::EBPF_SOURCE) {
            return startEBPFMonitoring();
        } else {
            return startKernelModuleMonitoring();
        }
    }

    void stopMonitoring() {
        monitoring_ = false;
        
        if (event_thread_.joinable()) {
            event_thread_.join();
        }

        if (program_loader_) {
            program_loader_->cleanup();
        }
    }

    EventSourceType getActiveSource() const {
        return source_type_;
    }

    static bool isEBPFSupported() {
        // Check kernel version >= 4.4
        struct utsname uts;
        if (uname(&uts) != 0) {
            return false;
        }

        int major, minor;
        if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
            return false;
        }

        if (major < 4 || (major == 4 && minor < 4)) {
            spdlog::info("Kernel version {}.{} does not support eBPF", major, minor);
            return false;
        }

        // Check if BPF syscall is available
        std::ifstream config("/proc/config.gz");
        if (!config.is_open()) {
            config.open("/boot/config-" + std::string(uts.release));
        }

        if (config.is_open()) {
            std::string line;
            while (std::getline(config, line)) {
                if (line.find("CONFIG_BPF_SYSCALL=y") != std::string::npos) {
                    return true;
                }
            }
        }

        // Check if /sys/kernel/debug/tracing/events/syscalls exists
        std::ifstream tracing("/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable");
        if (tracing.is_open()) {
            return true;
        }

        // Fallback check for /proc/sys/kernel/bpf_disabled
        std::ifstream bpf_disabled("/proc/sys/kernel/bpf_disabled");
        if (bpf_disabled.is_open()) {
            std::string value;
            std::getline(bpf_disabled, value);
            return value == "0";  // 0 means enabled
        }

        return false;
    }

private:
    bool initializeEBPFSource() {
        try {
            program_loader_ = std::make_unique<EBPFProgramLoader>();
            cache_merger_ = std::make_unique<EventCacheMerger>();
            netlink_sender_ = std::make_unique<NetlinkSender>();
            
            if (!program_loader_->loadProgram()) {
                spdlog::error("Failed to load eBPF program");
                return false;
            }

            if (!netlink_sender_->initialize()) {
                spdlog::error("Failed to initialize netlink sender");
                return false;
            }

            return true;
        } catch (const std::exception& e) {
            spdlog::error("Failed to initialize eBPF source: {}", e.what());
            return false;
        }
    }

    bool initializeKernelModule() {
        // Try to load existing kernel module
        int ret = system("modprobe vfs_monitor 2>/dev/null");
        if (ret == 0) {
            spdlog::info("Using kernel module event source");
            source_type_ = EventSourceType::KERNEL_MODULE_SOURCE;
            return true;
        }

        spdlog::error("Failed to load kernel module");
        return false;
    }

    bool startEBPFMonitoring() {
        event_thread_ = std::thread([this]() {
            this->ebpfEventLoop();
        });
        return true;
    }

    bool startKernelModuleMonitoring() {
        // Kernel module monitoring is handled by existing event_listenser
        // We just need to signal that we're using kernel module
        return true;
    }

    void ebpfEventLoop() {
        while (monitoring_) {
            // Read events from eBPF ring buffer
            auto events = program_loader_->readEvents();
            
            for (const auto& event : events) {
                // Process event through cache merger
                cache_merger_->addEvent(event);
            }

            // Flush expired events from cache
            auto merged_events = cache_merger_->flushExpiredEvents();
            
            for (const auto& event : merged_events) {
                // Send event via netlink
                if (netlink_sender_->sendEvent(event)) {
                    // Also call user callback if set
                    if (event_callback_) {
                        event_callback_(event);
                    }
                }
            }

            // Sleep briefly to avoid busy waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

private:
    EventSourceType source_type_;
    std::atomic<bool> monitoring_;
    EventCallback event_callback_;
    std::thread event_thread_;

    // eBPF components
    std::unique_ptr<EBPFProgramLoader> program_loader_;
    std::unique_ptr<EventCacheMerger> cache_merger_;
    std::unique_ptr<NetlinkSender> netlink_sender_;
};

EventManager::EventManager() : impl_(std::make_unique<Impl>()) {}

EventManager::~EventManager() {
    stopMonitoring();
}

bool EventManager::initialize() {
    return impl_->initialize();
}

bool EventManager::startMonitoring(EventCallback callback) {
    return impl_->startMonitoring(callback);
}

void EventManager::stopMonitoring() {
    impl_->stopMonitoring();
}

EventManager::EventSourceType EventManager::getActiveSource() const {
    return impl_->getActiveSource();
}

bool EventManager::isEBPFSupported() {
    return Impl::isEBPFSupported();
}

} // namespace ebpf 