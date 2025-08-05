// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "event_cache_merger.h"
#include <spdlog/spdlog.h>
#include <algorithm>

namespace ebpf {

class EventCacheMerger::Impl {
public:
    struct EventInfo {
        struct vfs_event event;
        std::chrono::steady_clock::time_point timestamp;
        bool paired{false};  // For rename events
        
        EventInfo(const struct vfs_event& e) 
            : event(e), timestamp(std::chrono::steady_clock::now()) {}
    };

    Impl() : window_duration_(1000) {}  // Default 1 second

    void addEvent(const struct vfs_event& event) {
        auto now = std::chrono::steady_clock::now();
        std::string path_key(event.path);
        
        // Try to merge with existing events
        if (tryMergeEvent(event, now)) {
            return;  // Event was merged or cancelled
        }
        
        // Add new event to cache
        cache_[path_key].emplace_back(event);
        
        spdlog::debug("Added event to cache: action={}, path={}", 
                     event.action, event.path);
    }

    std::vector<struct vfs_event> flushExpiredEvents() {
        std::vector<struct vfs_event> result;
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = cache_.begin(); it != cache_.end();) {
            auto& events = it->second;
            
            // Remove expired events and add them to result
            events.erase(
                std::remove_if(events.begin(), events.end(),
                    [&](const EventInfo& info) {
                        if (now - info.timestamp >= window_duration_) {
                            result.push_back(info.event);
                            return true;
                        }
                        return false;
                    }),
                events.end());
            
            // Remove empty entries
            if (events.empty()) {
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
        
        if (!result.empty()) {
            spdlog::debug("Flushed {} expired events from cache", result.size());
        }
        
        return result;
    }

    void clearCache() {
        cache_.clear();
        rename_pairs_.clear();
        spdlog::debug("Cleared event cache");
    }

    void setWindowDuration(std::chrono::milliseconds duration) {
        window_duration_ = duration;
    }

private:
    bool tryMergeEvent(const struct vfs_event& new_event, 
                      std::chrono::steady_clock::time_point now) {
        std::string path_key(new_event.path);
        
        auto it = cache_.find(path_key);
        if (it == cache_.end()) {
            return false;  // No existing events for this path
        }
        
        auto& events = it->second;
        
        // Try different merge strategies
        switch (new_event.action) {
            case ACT_DEL_FILE:
            case ACT_DEL_FOLDER:
                return tryMergeDelete(new_event, events, now);
                
            case ACT_NEW_FILE:
            case ACT_NEW_FOLDER:
                return tryMergeCreate(new_event, events, now);
                
            case ACT_RENAME_FROM_FILE:
            case ACT_RENAME_FROM_FOLDER:
                return tryMergeRenameFrom(new_event, events, now);
                
            case ACT_RENAME_TO_FILE:
            case ACT_RENAME_TO_FOLDER:
                return tryMergeRenameTo(new_event, events, now);
                
            default:
                return false;
        }
    }

    bool tryMergeDelete(const struct vfs_event& delete_event, 
                       std::vector<EventInfo>& events,
                       std::chrono::steady_clock::time_point now) {
        // Look for create events to cancel out
        for (auto it = events.begin(); it != events.end(); ++it) {
            if ((it->event.action == ACT_NEW_FILE && delete_event.action == ACT_DEL_FILE) ||
                (it->event.action == ACT_NEW_FOLDER && delete_event.action == ACT_DEL_FOLDER)) {
                
                // Check if within time window
                if (now - it->timestamp < window_duration_) {
                    spdlog::debug("Cancelled create+delete for path: {}", delete_event.path);
                    events.erase(it);
                    return true;  // Event cancelled
                }
            }
        }
        
        return false;  // No merge possible
    }

    bool tryMergeCreate(const struct vfs_event& create_event,
                       std::vector<EventInfo>& events,
                       std::chrono::steady_clock::time_point now) {
        // Look for delete events that this create might be replacing
        for (auto it = events.begin(); it != events.end(); ++it) {
            if ((it->event.action == ACT_DEL_FILE && create_event.action == ACT_NEW_FILE) ||
                (it->event.action == ACT_DEL_FOLDER && create_event.action == ACT_NEW_FOLDER)) {
                
                // Check if within time window
                if (now - it->timestamp < window_duration_) {
                    spdlog::debug("Cancelled delete+create for path: {}", create_event.path);
                    events.erase(it);
                    return true;  // Event cancelled
                }
            }
        }
        
        return false;
    }

    bool tryMergeRenameFrom(const struct vfs_event& rename_from,
                           std::vector<EventInfo>& /* events */,
                           std::chrono::steady_clock::time_point /* now */) {
        // Store rename_from event and wait for corresponding rename_to
        rename_pairs_[rename_from.cookie] = rename_from;
        return false;  // Don't add to cache yet
    }

    bool tryMergeRenameTo(const struct vfs_event& rename_to,
                         std::vector<EventInfo>& /* events */,
                         std::chrono::steady_clock::time_point /* now */) {
        // Look for matching rename_from event
        auto it = rename_pairs_.find(rename_to.cookie);
        if (it != rename_pairs_.end()) {
            // Found matching rename_from, create combined rename event
            struct vfs_event combined = rename_to;
            combined.action = (rename_to.action == ACT_RENAME_TO_FILE) ? 
                             ACT_RENAME_FILE : ACT_RENAME_FOLDER;
            
            // Add to old path cache to handle potential merges
            std::string old_path(it->second.path);
            cache_[old_path].emplace_back(combined);
            
            // Remove from rename pairs
            rename_pairs_.erase(it);
            
            spdlog::debug("Combined rename: {} -> {}", it->second.path, rename_to.path);
            return true;  // Event was handled
        }
        
        return false;  // No matching rename_from found
    }

private:
    std::unordered_map<std::string, std::vector<EventInfo>> cache_;
    std::unordered_map<uint32_t, struct vfs_event> rename_pairs_;  // cookie -> rename_from event
    std::chrono::milliseconds window_duration_;
};

EventCacheMerger::EventCacheMerger() : impl_(std::make_unique<Impl>()) {}

EventCacheMerger::~EventCacheMerger() = default;

void EventCacheMerger::addEvent(const struct vfs_event& event) {
    impl_->addEvent(event);
}

std::vector<struct vfs_event> EventCacheMerger::flushExpiredEvents() {
    return impl_->flushExpiredEvents();
}

void EventCacheMerger::clearCache() {
    impl_->clearCache();
}

void EventCacheMerger::setWindowDuration(std::chrono::milliseconds duration) {
    impl_->setWindowDuration(duration);
}

} // namespace ebpf 