// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef EVENT_DEDUPLICATOR_H
#define EVENT_DEDUPLICATOR_H

#include <vector>
#include <unordered_map>
#include <chrono>
#include <string>
#include <mutex>

#include "../include/ebpf_common.h"

namespace ebpf {

class EventDeduplicator {
public:
    enum EventPriority {
        VFS_PRIORITY = 3,      // Highest priority - VFS layer events
        SYSCALL_PRIORITY = 2,  // Medium priority - Syscall events  
        MMAP_PRIORITY = 1      // Lowest priority - Memory map events
    };

    struct EventFingerprint {
        std::string path;
        uint8_t action;
        uint32_t pid;
        uint16_t major;
        uint8_t minor;
        
        bool operator==(const EventFingerprint& other) const {
            return path == other.path && 
                   action == other.action && 
                   pid == other.pid &&
                   major == other.major &&
                   minor == other.minor;
        }
    };
    
    struct EventInfo {
        vfs_event event;
        EventPriority priority;
        std::chrono::steady_clock::time_point timestamp;
        uint32_t source_type; // VFS, SYSCALL, MMAP
    };

    EventDeduplicator();
    ~EventDeduplicator();

    // Process incoming event and return deduplicated events
    std::vector<vfs_event> processEvent(const vfs_event& event, 
                                       EventPriority priority = SYSCALL_PRIORITY,
                                       uint32_t source_type = 0);
    
    // Flush expired events
    std::vector<vfs_event> flushExpiredEvents();
    
    // Clear all cached events
    void clearCache();
    
    // Configuration
    void setTimeWindow(std::chrono::milliseconds window);
    void setMaxCacheSize(size_t max_size);
    
    // Statistics
    struct Stats {
        uint64_t total_events_processed;
        uint64_t events_deduplicated;
        uint64_t events_emitted;
        uint64_t cache_hits;
        uint64_t cache_misses;
    };
    
    Stats getStats() const;
    void resetStats();

private:
    EventFingerprint createFingerprint(const vfs_event& event);
    std::string fingerprintToString(const EventFingerprint& fp);
    bool shouldReplaceEvent(const EventInfo& existing, const EventInfo& new_event);
    void cleanupExpiredEvents();

private:
    std::unordered_map<std::string, EventInfo> event_cache_;
    std::chrono::milliseconds time_window_;
    size_t max_cache_size_;
    
    mutable std::mutex cache_mutex_;
    Stats stats_;
    
    std::chrono::steady_clock::time_point last_cleanup_;
};

} // namespace ebpf

// Hash function for EventFingerprint
namespace std {
template<>
struct hash<ebpf::EventDeduplicator::EventFingerprint> {
    size_t operator()(const ebpf::EventDeduplicator::EventFingerprint& fp) const {
        size_t h1 = std::hash<std::string>{}(fp.path);
        size_t h2 = std::hash<uint8_t>{}(fp.action);
        size_t h3 = std::hash<uint32_t>{}(fp.pid);
        size_t h4 = std::hash<uint16_t>{}(fp.major);
        size_t h5 = std::hash<uint8_t>{}(fp.minor);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};
}

#endif // EVENT_DEDUPLICATOR_H