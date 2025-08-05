// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "../include/ebpf_common.h"
#include <vector>
#include <memory>

namespace ebpf {

class EBPFProgramLoader {
public:
    EBPFProgramLoader();
    ~EBPFProgramLoader();

    // Load eBPF program and attach to tracepoints
    bool loadProgram();
    
    // Read events from ring buffer
    std::vector<struct vfs_event> readEvents();
    
    // Cleanup resources
    void cleanup();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ebpf 