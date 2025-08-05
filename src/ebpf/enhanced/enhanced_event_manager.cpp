// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "enhanced_event_manager.h"

#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

#include "vfs_layer_monitor.h"
#include "memory_map_monitor.h"
#include "fexit_production_monitor.h"
#include "event_deduplicator.h"
#include "performance_monitor.h"
#include "event_manager.h"

namespace ebpf {

EnhancedEventManager::EnhancedEventManager()
    : current_strategy_(KERNEL_MODULE)
    , initialized_(false)
    , monitoring_(false) {
}

EnhancedEventManager::~EnhancedEventManager() {
    stopMonitoring();
}

bool EnhancedEventManager::initialize() {
    if (initialized_) {
        return true;
    }

    // Detect system capabilities
    capabilities_ = detectCapabilities();
    
    // Select optimal monitoring strategy
    current_strategy_ = selectOptimalStrategy();
    
    // Initialize based on selected strategy
    bool success = false;
    switch (current_strategy_) {
        case FEXIT_PRODUCTION:
            success = initializeFexitProduction();
            break;
        case FULL_COVERAGE:
            success = initializeFullCoverage();
            break;
        case SYSCALL_ONLY:
            success = initializeSyscallOnly();
            break;
        case KERNEL_MODULE:
            success = initializeKernelModule();
            break;
    }
    
    if (success) {
        initialized_ = true;
        printf("Enhanced Event Manager initialized with strategy: %s\n",
               current_strategy_ == FEXIT_PRODUCTION ? "FEXIT_PRODUCTION" :
               current_strategy_ == FULL_COVERAGE ? "FULL_COVERAGE" :
               current_strategy_ == SYSCALL_ONLY ? "SYSCALL_ONLY" : "KERNEL_MODULE");
    }
    
    return success;
}

EnhancedEventManager::MonitoringStrategy EnhancedEventManager::selectOptimalStrategy() {
    // 🚀 Strategy selection algorithm based on capabilities
    
    // First priority: Fexit production monitoring (kernel 5.5+)
    if (capabilities_.supports_fexit && 
        (capabilities_.has_cap_bpf || capabilities_.has_cap_sys_admin)) {
        std::cout << "🎯 Selected FEXIT_PRODUCTION strategy (optimal)" << std::endl;
        return FEXIT_PRODUCTION;
    }
    
    // Second priority: Full coverage with traditional eBPF
    if ((capabilities_.vfs_tracepoints_available || capabilities_.vfs_kprobe_available) && 
        capabilities_.syscall_tracepoints_available &&
        (capabilities_.has_cap_bpf || capabilities_.has_cap_sys_admin)) {
        std::cout << "🔧 Selected FULL_COVERAGE strategy (traditional eBPF)" << std::endl;
        return FULL_COVERAGE;
    }
    
    // Third priority: Syscall-only mode
    if (capabilities_.syscall_tracepoints_available &&
        (capabilities_.has_cap_bpf || capabilities_.has_cap_sys_admin)) {
        std::cout << "⚠️ Selected SYSCALL_ONLY strategy (limited)" << std::endl;
        return SYSCALL_ONLY;
    }
    
    // Fallback to kernel module
    std::cout << "🔙 Selected KERNEL_MODULE strategy (fallback)" << std::endl;
    return KERNEL_MODULE;
}

EnhancedEventManager::MonitoringCapabilities EnhancedEventManager::detectCapabilities() {
    MonitoringCapabilities caps = {};
    
    // Parse kernel version
    int version = parseKernelVersion();
    caps.kernel_version_major = version >> 16;
    caps.kernel_version_minor = (version >> 8) & 0xFF;
    
    // Check fexit support first (kernel 5.5+)
    caps.supports_fexit = (caps.kernel_version_major > 5 || 
                          (caps.kernel_version_major == 5 && caps.kernel_version_minor >= 5));
    
    // Check various capabilities
    caps.vfs_tracepoints_available = checkVFSTracepointsAvailable();
    caps.vfs_kprobe_available = checkVFSKprobeAvailable();
    caps.mm_tracepoints_available = checkMMTracepointsAvailable();
    caps.syscall_tracepoints_available = checkSyscallTracepointsAvailable();
    caps.has_cap_bpf = checkCapabilities();
    caps.has_cap_sys_admin = (geteuid() == 0);
    
    return caps;
}

bool EnhancedEventManager::startMonitoring() {
    if (!initialized_) {
        printf("Enhanced Event Manager not initialized\n");
        return false;
    }
    
    if (monitoring_) {
        return true;
    }
    
    if (!event_handler_) {
        printf("No event handler set\n");
        return false;
    }
    
    bool success = false;
    
    // Create event handler with deduplication and performance monitoring
    auto dedup_handler = [this](const vfs_event& event) {
        // Record performance stats
        if (perf_monitor_) {
            std::string source_name;
            
            switch (event.source_type) {
                case 1: // VFS_SOURCE
                    source_name = "VFS";
                    break;
                case 0: // SYSCALL_SOURCE  
                    source_name = "SYSCALL";
                    break;
                case 2: // MMAP_SOURCE
                    source_name = "MMAP";
                    break;
                default:
                    source_name = "UNKNOWN";
                    break;
            }
            
            perf_monitor_->recordEvent(source_name);
        }
        
        if (deduplicator_) {
            EventDeduplicator::EventPriority priority = EventDeduplicator::SYSCALL_PRIORITY;
            switch (event.source_type) {
                case 1: priority = EventDeduplicator::VFS_PRIORITY; break;
                case 2: priority = EventDeduplicator::MMAP_PRIORITY; break;
                default: break;
            }
            
            auto deduped_events = deduplicator_->processEvent(event, priority, event.source_type);
            
            // Record deduplication stats
            if (perf_monitor_ && deduped_events.empty()) {
                perf_monitor_->recordDuplicate();
            }
            
            for (const auto& deduped_event : deduped_events) {
                if (perf_monitor_) {
                    perf_monitor_->recordProcessed();
                }
                if (event_handler_) {
                    event_handler_(deduped_event);
                }
            }
        } else if (event_handler_) {
            if (perf_monitor_) {
                perf_monitor_->recordProcessed();
            }
            event_handler_(event);
        }
    };
    
    switch (current_strategy_) {
        case FEXIT_PRODUCTION:
            // 🚀 使用新的Fexit生产监控器
            if (fexit_monitor_) {
                auto fexit_handler = [dedup_handler](const vfs_event* event) {
                    if (event) {
                        dedup_handler(*event);
                    }
                };
                success = fexit_monitor_->startMonitoring(fexit_handler);
                if (success) {
                    std::cout << "🎯 Fexit Production Monitor started successfully" << std::endl;
                }
            }
            break;
            
        case FULL_COVERAGE:
            if (vfs_monitor_) {
                success = vfs_monitor_->start();
            }
            if (success && syscall_monitor_) {
                success = syscall_monitor_->startMonitoring(dedup_handler);
            }
            if (success && mmap_monitor_) {
                // Try to start mmap monitoring, but don't fail if it's not available
                mmap_monitor_->start();
            }
            break;
            
        case SYSCALL_ONLY:
            if (syscall_monitor_) {
                success = syscall_monitor_->startMonitoring(dedup_handler);
            }
            break;
            
        case KERNEL_MODULE:
            if (syscall_monitor_) {
                success = syscall_monitor_->startMonitoring(dedup_handler);
            }
            break;
    }
    
    if (success) {
        // Start performance monitoring
        if (perf_monitor_) {
            perf_monitor_->start();
        }
        
        monitoring_ = true;
        printf("Monitoring started with strategy: %s\n",
               current_strategy_ == FULL_COVERAGE ? "FULL_COVERAGE" :
               current_strategy_ == SYSCALL_ONLY ? "SYSCALL_ONLY" : "KERNEL_MODULE");
    }
    
    return success;
}

void EnhancedEventManager::stopMonitoring() {
    if (!monitoring_) {
        return;
    }
    
    // Stop Fexit monitor
    if (fexit_monitor_) {
        fexit_monitor_->stopMonitoring();
    }
    
    if (vfs_monitor_) {
        vfs_monitor_->stop();
    }
    
    if (mmap_monitor_) {
        mmap_monitor_->stop();
    }
    
    if (syscall_monitor_) {
        syscall_monitor_->stopMonitoring();
    }
    
    // Stop performance monitoring and print final stats
    if (perf_monitor_) {
        perf_monitor_->printStats();
        perf_monitor_->stop();
    }
    
    monitoring_ = false;
    printf("Enhanced monitoring stopped\n");
}

void EnhancedEventManager::setEventHandler(std::function<void(const vfs_event&)> handler) {
    event_handler_ = handler;
}

void EnhancedEventManager::printPerformanceStats() const {
    if (perf_monitor_) {
        perf_monitor_->printStats();
    }
}

double EnhancedEventManager::getEventsPerSecond() const {
    if (perf_monitor_) {
        return perf_monitor_->getEventsPerSecond();
    }
    return 0.0;
}

bool EnhancedEventManager::initializeFexitProduction() {
    std::cout << "🚀 Initializing Fexit Production monitoring..." << std::endl;
    
    // Initialize performance monitor
    perf_monitor_ = std::make_unique<PerformanceMonitor>();
    
    // Initialize Fexit production monitor
    fexit_monitor_ = std::make_unique<FexitProductionMonitor>();
    if (!fexit_monitor_->initialize()) {
        std::cerr << "❌ Failed to initialize Fexit Production Monitor" << std::endl;
        return false;
    }
    
    std::cout << "✅ Fexit Production monitoring initialized successfully" << std::endl;
    return true;
}

bool EnhancedEventManager::initializeFullCoverage() {
    // Initialize event deduplicator
    deduplicator_ = std::make_unique<EventDeduplicator>();
    
    // Initialize performance monitor
    perf_monitor_ = std::make_unique<PerformanceMonitor>();
    
    // Initialize VFS layer monitor
    vfs_monitor_ = std::make_unique<VFSLayerMonitor>();
    if (!vfs_monitor_->initialize()) {
        printf("Failed to initialize VFS layer monitor\n");
        return false;
    }
    
    // Initialize memory map monitor (optional)
    mmap_monitor_ = std::make_unique<MemoryMapMonitor>();
    mmap_monitor_->initialize(); // Don't fail if this doesn't work
    
    // Initialize syscall monitor
    syscall_monitor_ = std::make_unique<EventManager>();
    if (!syscall_monitor_->initialize()) {
        printf("Failed to initialize syscall monitor\n");
        return false;
    }
    
    return true;
}

bool EnhancedEventManager::initializeSyscallOnly() {
    // Initialize syscall monitor only
    syscall_monitor_ = std::make_unique<EventManager>();
    return syscall_monitor_->initialize();
}

bool EnhancedEventManager::initializeKernelModule() {
    // Initialize with kernel module fallback
    syscall_monitor_ = std::make_unique<EventManager>();
    return syscall_monitor_->initialize();
}

bool EnhancedEventManager::checkVFSTracepointsAvailable() {
    // Check if VFS tracepoints are available
    struct stat st;
    return (stat("/sys/kernel/debug/tracing/events/vfs", &st) == 0);
}

bool EnhancedEventManager::checkVFSKprobeAvailable() {
    // Check if kprobes are available and we can probe VFS functions
    struct stat st;
    if (stat("/sys/kernel/debug/tracing/kprobe_events", &st) != 0) {
        return false;
    }
    
    // Check if vfs_* symbols are available
    std::ifstream kallsyms("/proc/kallsyms");
    if (!kallsyms.is_open()) {
        return false;
    }
    
    std::string line;
    bool found_vfs_create = false;
    bool found_vfs_unlink = false;
    
    while (std::getline(kallsyms, line)) {
        if (line.find("vfs_create") != std::string::npos) {
            found_vfs_create = true;
        }
        if (line.find("vfs_unlink") != std::string::npos) {
            found_vfs_unlink = true;
        }
        if (found_vfs_create && found_vfs_unlink) {
            break;
        }
    }
    
    return found_vfs_create && found_vfs_unlink;
}

bool EnhancedEventManager::checkMMTracepointsAvailable() {
    // Check if memory management tracepoints are available
    struct stat st;
    return (stat("/sys/kernel/debug/tracing/events/writeback", &st) == 0);
}

bool EnhancedEventManager::checkSyscallTracepointsAvailable() {
    // Check if syscall tracepoints are available
    struct stat st;
    return (stat("/sys/kernel/debug/tracing/events/syscalls", &st) == 0);
}

bool EnhancedEventManager::checkCapabilities() {
    // Simple capability check - if we're root, we have the necessary capabilities
    // For more detailed capability checking, libcap would be needed
    if (geteuid() == 0) {
        return true;
    }
    
    // Try to check capabilities via /proc/self/status
    std::ifstream status_file("/proc/self/status");
    if (!status_file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(status_file, line)) {
        if (line.find("CapEff:") == 0) {
            // Parse effective capabilities
            // This is a simplified check - for production, use libcap
            std::string caps_hex = line.substr(7);
            // Remove whitespace
            caps_hex.erase(0, caps_hex.find_first_not_of(" \t"));
            
            // If capabilities are not empty, assume we have some privileges
            return !caps_hex.empty() && caps_hex != "0000000000000000";
        }
    }
    
    return false;
}

int EnhancedEventManager::parseKernelVersion() {
    struct utsname uts;
    if (uname(&uts) != 0) {
        return 0;
    }
    
    int major, minor, patch;
    if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) != 3) {
        return 0;
    }
    
    return (major << 16) | (minor << 8) | patch;
}

} // namespace ebpf