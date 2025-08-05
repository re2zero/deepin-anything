// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf_program_loader.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <spdlog/spdlog.h>

// Include generated eBPF bytecode
#include "vfs_monitor_bytecode.h"

namespace ebpf {

class EBPFProgramLoader::Impl {
public:
    Impl() : obj_(nullptr), 
             events_map_fd_(-1),
             ring_buffer_(nullptr) {
        // Initialize program file descriptors
        for (auto& fd : prog_fds_) {
            fd = -1;
        }
    }

    ~Impl() {
        cleanup();
    }

    bool loadProgram() {
        // Load eBPF object from embedded bytecode
        struct bpf_object_open_opts opts = {};
        opts.sz = sizeof(struct bpf_object_open_opts);
        obj_ = bpf_object__open_mem(vfs_monitor_o, vfs_monitor_o_len, &opts);
        if (libbpf_get_error(obj_)) {
            spdlog::error("Failed to open eBPF object: {}", strerror(errno));
            return false;
        }

        // Load object into kernel
        if (bpf_object__load(obj_)) {
            spdlog::error("Failed to load eBPF object into kernel");
            cleanup();
            return false;
        }

        // Get ring buffer map
        struct bpf_map *events_map = bpf_object__find_map_by_name(obj_, "events");
        if (!events_map) {
            spdlog::error("Failed to find events map");
            cleanup();
            return false;
        }
        events_map_fd_ = bpf_map__fd(events_map);

        // Attach programs to tracepoints
        if (!attachPrograms()) {
            cleanup();
            return false;
        }

        // Setup ring buffer
        ring_buffer_ = ring_buffer__new(events_map_fd_, handleEvent, this, nullptr);
        if (!ring_buffer_) {
            spdlog::error("Failed to create ring buffer");
            cleanup();
            return false;
        }

        spdlog::info("eBPF program loaded and attached successfully");
        return true;
    }

    std::vector<struct vfs_event> readEvents() {
        std::vector<struct vfs_event> events;
        
        if (!ring_buffer_) {
            return events;
        }

        // Clear previous events
        pending_events_.clear();
        
        // Poll ring buffer with timeout
        int ret = ring_buffer__poll(ring_buffer_, 100); // 100ms timeout
        if (ret < 0) {
            spdlog::debug("Ring buffer poll error: {}", ret);
        }

        // Return collected events
        events = std::move(pending_events_);
        return events;
    }

    void cleanup() {
        // Detach programs
        for (auto& link : links_) {
            if (link) {
                bpf_link__destroy(link);
                link = nullptr;
            }
        }

        // Close ring buffer
        if (ring_buffer_) {
            ring_buffer__free(ring_buffer_);
            ring_buffer_ = nullptr;
        }

        // Close object
        if (obj_) {
            bpf_object__close(obj_);
            obj_ = nullptr;
        }

        events_map_fd_ = -1;
    }

private:
    bool attachPrograms() {
        const char* tracepoints[] = {
            "syscalls/sys_enter_openat",
            "syscalls/sys_enter_unlinkat", 
            "syscalls/sys_enter_unlink",
            "syscalls/sys_enter_renameat2",
            "syscalls/sys_enter_rename"
        };

        const char* program_names[] = {
            "trace_openat",
            "trace_unlinkat",
            "trace_unlink", 
            "trace_renameat2",
            "trace_rename"
        };

        for (size_t i = 0; i < sizeof(tracepoints) / sizeof(tracepoints[0]); i++) {
            struct bpf_program *prog = bpf_object__find_program_by_name(obj_, program_names[i]);
            if (!prog) {
                spdlog::error("Failed to find program: {}", program_names[i]);
                return false;
            }

            struct bpf_link *link = bpf_program__attach_tracepoint(prog, "syscalls", 
                                        strrchr(tracepoints[i], '/') + 1);
            if (libbpf_get_error(link)) {
                spdlog::error("Failed to attach program {} to tracepoint {}", 
                            program_names[i], tracepoints[i]);
                return false;
            }

            links_.push_back(link);
            spdlog::debug("Attached {} to {}", program_names[i], tracepoints[i]);
        }

        return true;
    }

    static int handleEvent(void *ctx, void *data, size_t data_sz) {
        auto *loader = static_cast<EBPFProgramLoader::Impl*>(ctx);
        
        if (data_sz < sizeof(struct vfs_event)) {
            spdlog::warn("Received event with invalid size: {}", data_sz);
            return 0;
        }

        struct vfs_event event;
        memcpy(&event, data, sizeof(event));
        
        // Add to pending events
        loader->pending_events_.push_back(event);
        
        return 0;
    }

private:
    struct bpf_object *obj_;
    int events_map_fd_;
    int prog_fds_[5]; // For 5 tracepoint programs
    std::vector<struct bpf_link*> links_;
    struct ring_buffer *ring_buffer_;
    std::vector<struct vfs_event> pending_events_;
};

EBPFProgramLoader::EBPFProgramLoader() : impl_(std::make_unique<Impl>()) {}

EBPFProgramLoader::~EBPFProgramLoader() {
    cleanup();
}

bool EBPFProgramLoader::loadProgram() {
    return impl_->loadProgram();
}

std::vector<struct vfs_event> EBPFProgramLoader::readEvents() {
    return impl_->readEvents();
}

void EBPFProgramLoader::cleanup() {
    impl_->cleanup();
}

} // namespace ebpf 