// Copyright (C) 2024 UOS Technology Co., Ltd.
// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "netlink_sender.h"
#include "../../server/include/common/vfs_genl.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <string>

namespace ebpf {

class NetlinkSender::Impl {
public:
    Impl() : sk_(nullptr), family_id_(-1) {}

    ~Impl() {
        cleanup();
    }

    bool initialize() {
        // Create netlink socket
        sk_ = nl_socket_alloc();
        if (!sk_) {
            spdlog::error("Failed to allocate netlink socket");
            return false;
        }

        // Connect to generic netlink
        if (genl_connect(sk_) < 0) {
            spdlog::error("Failed to connect to generic netlink");
            cleanup();
            return false;
        }

        // Resolve family ID
        family_id_ = genl_ctrl_resolve(sk_, VFSMONITOR_FAMILY_NAME);
        if (family_id_ < 0) {
            spdlog::error("Failed to resolve generic netlink family: {}", VFSMONITOR_FAMILY_NAME);
            cleanup();
            return false;
        }

        spdlog::info("Netlink sender initialized, family ID: {}", family_id_);
        return true;
    }

    bool sendEvent(const struct vfs_event& event) {
        if (!sk_ || family_id_ < 0) {
            return false;
        }

        // Create message
        struct nl_msg *msg = nlmsg_alloc();
        if (!msg) {
            spdlog::error("Failed to allocate netlink message");
            return false;
        }

        // Add generic netlink header
        void *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id_, 0, 
                               NLM_F_REQUEST, VFSMONITOR_C_NOTIFY, 1);
        if (!hdr) {
            spdlog::error("Failed to add generic netlink header");
            nlmsg_free(msg);
            return false;
        }

        // Get device info from path
        uint16_t dev_major = 0;
        uint8_t dev_minor = 0;
        getDeviceInfo(event.path, &dev_major, &dev_minor);

        // Add attributes (compatible with existing kernel module format)
        if (nla_put_u8(msg, VFSMONITOR_A_ACT, event.action) < 0 ||
            nla_put_u32(msg, VFSMONITOR_A_COOKIE, event.cookie) < 0 ||
            nla_put_u16(msg, VFSMONITOR_A_MAJOR, dev_major) < 0 ||
            nla_put_u8(msg, VFSMONITOR_A_MINOR, dev_minor) < 0 ||
            nla_put_string(msg, VFSMONITOR_A_PATH, event.path) < 0) {
            
            spdlog::error("Failed to add netlink attributes");
            nlmsg_free(msg);
            return false;
        }

        // Send multicast message
        int ret = nl_send_auto(sk_, msg);
        nlmsg_free(msg);

        if (ret < 0) {
            spdlog::error("Failed to send netlink message: {}", nl_geterror(ret));
            return false;
        }

        spdlog::debug("Sent event via netlink: action={}, path={}", event.action, event.path);
        return true;
    }

    void cleanup() {
        if (sk_) {
            nl_socket_free(sk_);
            sk_ = nullptr;
        }
        family_id_ = -1;
    }

private:
    void getDeviceInfo(const char* path, uint16_t* dev_major, uint8_t* dev_minor) {
        struct stat st;
        if (stat(path, &st) == 0) {
            *dev_major = major(st.st_dev);
            *dev_minor = minor(st.st_dev);
        } else {
            // If stat fails, try to get device info from parent directory
            std::string dir_path(path);
            size_t pos = dir_path.find_last_of('/');
            if (pos != std::string::npos) {
                dir_path = dir_path.substr(0, pos);
                if (!dir_path.empty() && stat(dir_path.c_str(), &st) == 0) {
                    *dev_major = major(st.st_dev);
                    *dev_minor = minor(st.st_dev);
                    return;
                }
            }
            
            // Fallback to default values
            *dev_major = 0;
            *dev_minor = 0;
        }
    }

private:
    struct nl_sock *sk_;
    int family_id_;
};

NetlinkSender::NetlinkSender() : impl_(std::make_unique<Impl>()) {}

NetlinkSender::~NetlinkSender() {
    cleanup();
}

bool NetlinkSender::initialize() {
    return impl_->initialize();
}

bool NetlinkSender::sendEvent(const struct vfs_event& event) {
    return impl_->sendEvent(event);
}

void NetlinkSender::cleanup() {
    impl_->cleanup();
}

} // namespace ebpf 