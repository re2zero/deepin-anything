// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "event_deduplicator.h"

#include <algorithm>
#include <sstream>

namespace ebpf {

EventDeduplicator::EventDeduplicator()
    : time_window_(std::chrono::milliseconds(1000))  // 1 second default
    , max_cache_size_(10000)  // Maximum 10k events in cache
    , stats_{}
    , last_cleanup_(std::chrono::steady_clock::now()) {
}

EventDeduplicator::~EventDeduplicator() {
    clearCache();
}

std::vector<vfs_event> EventDeduplicator::processEvent(const vfs_event& event, 
                                                      EventPriority priority,
                                                      uint32_t source_type) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    stats_.total_events_processed++;
    
    // Create fingerprint for the event
    EventFingerprint fingerprint = createFingerprint(event);
    std::string fp_key = fingerprintToString(fingerprint);
    
    auto now = std::chrono::steady_clock::now();
    
    // Check if we have this event in cache
    auto it = event_cache_.find(fp_key);
    if (it != event_cache_.end()) {
        stats_.cache_hits++;
        
        // Check if the cached event is still within time window
        auto time_diff = now - it->second.timestamp;
        if (time_diff <= time_window_) {
            // Event is within time window, check if we should replace it
            EventInfo new_event_info = {event, priority, now, source_type};
            
            if (shouldReplaceEvent(it->second, new_event_info)) {
                it->second = new_event_info;
            }
            
            stats_.events_deduplicated++;
            return {}; // No events to emit, deduplicated
        } else {
            // Event expired, remove from cache and continue processing
            event_cache_.erase(it);
        }
    } else {
        stats_.cache_misses++;
    }
    
    // Add new event to cache
    EventInfo event_info = {event, priority, now, source_type};
    event_cache_[fp_key] = event_info;
    
    // Check cache size limit
    if (event_cache_.size() > max_cache_size_) {
        cleanupExpiredEvents();
        
        // If still over limit, remove oldest events
        if (event_cache_.size() > max_cache_size_) {
            // Find and remove oldest events
            std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> entries;
            for (const auto& pair : event_cache_) {
                entries.emplace_back(pair.first, pair.second.timestamp);
            }
            
            std::sort(entries.begin(), entries.end(), 
                     [](const auto& a, const auto& b) {
                         return a.second < b.second;
                     });
            
            size_t to_remove = event_cache_.size() - max_cache_size_ + 1000; // Remove extra
            for (size_t i = 0; i < to_remove && i < entries.size(); ++i) {
                event_cache_.erase(entries[i].first);
            }
        }
    }
    
    // Periodic cleanup
    if (now - last_cleanup_ > std::chrono::seconds(10)) {
        cleanupExpiredEvents();
        last_cleanup_ = now;
    }
    
    stats_.events_emitted++;
    return {event}; // Return the event to be processed
}

std::vector<vfs_event> EventDeduplicator::flushExpiredEvents() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    std::vector<vfs_event> expired_events;
    auto now = std::chrono::steady_clock::now();
    
    auto it = event_cache_.begin();
    while (it != event_cache_.end()) {
        auto time_diff = now - it->second.timestamp;
        if (time_diff > time_window_) {
            expired_events.push_back(it->second.event);
            it = event_cache_.erase(it);
        } else {
            ++it;
        }
    }
    
    stats_.events_emitted += expired_events.size();
    return expired_events;
}

void EventDeduplicator::clearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    event_cache_.clear();
}

void EventDeduplicator::setTimeWindow(std::chrono::milliseconds window) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    time_window_ = window;
}

void EventDeduplicator::setMaxCacheSize(size_t max_size) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    max_cache_size_ = max_size;
}

EventDeduplicator::Stats EventDeduplicator::getStats() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return stats_;
}

void EventDeduplicator::resetStats() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    stats_ = {};
}

EventDeduplicator::EventFingerprint EventDeduplicator::createFingerprint(const vfs_event& event) {
    EventFingerprint fp;
    fp.path = std::string(event.path);
    fp.action = event.action;
    fp.pid = event.pid;
    fp.major = event.major;
    fp.minor = event.minor;
    return fp;
}

std::string EventDeduplicator::fingerprintToString(const EventFingerprint& fp) {
    std::ostringstream oss;
    oss << fp.path << "|" << static_cast<int>(fp.action) << "|" 
        << fp.pid << "|" << fp.major << "|" << static_cast<int>(fp.minor);
    return oss.str();
}

bool EventDeduplicator::shouldReplaceEvent(const EventInfo& existing, const EventInfo& new_event) {
    // Replace if new event has higher priority
    if (new_event.priority > existing.priority) {
        return true;
    }
    
    // If same priority, replace if newer timestamp
    if (new_event.priority == existing.priority) {
        return new_event.timestamp > existing.timestamp;
    }
    
    return false;
}

void EventDeduplicator::cleanupExpiredEvents() {
    auto now = std::chrono::steady_clock::now();
    
    auto it = event_cache_.begin();
    while (it != event_cache_.end()) {
        auto time_diff = now - it->second.timestamp;
        if (time_diff > time_window_) {
            it = event_cache_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace ebpf