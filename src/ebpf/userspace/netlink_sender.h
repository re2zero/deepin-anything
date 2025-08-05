// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "../include/ebpf_common.h"
#include <memory>

namespace ebpf {

class NetlinkSender {
public:
    NetlinkSender();
    ~NetlinkSender();

    // Initialize netlink socket
    bool initialize();
    
    // Send VFS event via netlink (compatible with existing protocol)
    bool sendEvent(const struct vfs_event& event);
    
    // Cleanup resources
    void cleanup();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ebpf 