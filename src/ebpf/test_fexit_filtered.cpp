#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "include/ebpf_common.h"

// Include the generated eBPF bytecode
#include "fexit_filesystem_monitor_bytecode.h"

class FexitFilteredTest {
public:
    FexitFilteredTest() : total_events_(0), vfs_events_(0), 
                         syscall_events_(0), filtered_events_(0), 
                         relevant_events_(0) {}
    
    ~FexitFilteredTest() {
        cleanup();
    }
    
    bool initialize() {
        std::cout << "🚀 Initializing Filtered Fexit Monitor..." << std::endl;
        
        // Load eBPF program
        struct bpf_object_open_opts opts = {};
        opts.sz = sizeof(struct bpf_object_open_opts);
        
        obj_ = bpf_object__open_mem(fexit_filesystem_monitor_o, 
                                   fexit_filesystem_monitor_o_len, &opts);
        if (!obj_) {
            std::cerr << "❌ Failed to open eBPF object" << std::endl;
            return false;
        }
        
        // Load the program into kernel
        if (bpf_object__load(obj_) != 0) {
            std::cerr << "❌ Failed to load eBPF program" << std::endl;
            return false;
        }
        
        std::cout << "✅ Fexit eBPF program loaded successfully" << std::endl;
        
        return attachFexitPrograms();
    }
    
    bool attachFexitPrograms() {
        std::cout << "🔗 Attaching filtered fexit programs..." << std::endl;
        
        // List of fexit programs to attach
        const char* fexit_programs[] = {
            "fexit_vfs_create",
            "fexit_vfs_mkdir", 
            "fexit_vfs_unlink",
            "fexit_vfs_rmdir",
            "fexit_vfs_rename",
            "fexit_sys_openat2"
        };
        
        int attached_count = 0;
        for (const char* prog_name : fexit_programs) {
            struct bpf_program *prog = bpf_object__find_program_by_name(obj_, prog_name);
            if (prog) {
                struct bpf_link *link = bpf_program__attach(prog);
                if (link) {
                    fexit_links_.push_back(link);
                    attached_count++;
                    std::cout << "✅ Attached fexit: " << prog_name << std::endl;
                } else {
                    std::cout << "⚠️ Failed to attach: " << prog_name << std::endl;
                }
            } else {
                std::cout << "⚠️ Program not found: " << prog_name << std::endl;
            }
        }
        
        std::cout << "📊 Attached " << attached_count << "/" 
                  << sizeof(fexit_programs)/sizeof(fexit_programs[0]) 
                  << " fexit programs" << std::endl;
        
        return setupRingBuffer();
    }
    
    bool setupRingBuffer() {
        struct bpf_map *map = bpf_object__find_map_by_name(obj_, "fexit_fs_events");
        if (!map) {
            std::cerr << "❌ Failed to find ring buffer map" << std::endl;
            return false;
        }
        
        ring_buf_ = ring_buffer__new(bpf_map__fd(map), handleRingBufferEvent, this, nullptr);
        if (!ring_buf_) {
            std::cerr << "❌ Failed to create ring buffer" << std::endl;
            return false;
        }
        
        std::cout << "✅ Ring buffer setup successful" << std::endl;
        return true;
    }
    
    void startFilteredTest() {
        std::cout << "\n🎯 === Starting Filtered Fexit Test ===" << std::endl;
        std::cout << "目标：验证智能过滤的文件系统监控" << std::endl;
        
        is_running_ = true;
        polling_thread_ = std::thread(&FexitFilteredTest::pollRingBuffer, this);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 执行文件系统操作测试
        performFileSystemTest();
        
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        is_running_ = false;
        if (polling_thread_.joinable()) {
            polling_thread_.join();
        }
        
        printFilteredResults(duration);
    }
    
private:
    struct bpf_object *obj_;
    std::vector<struct bpf_link*> fexit_links_;
    struct ring_buffer *ring_buf_;
    std::thread polling_thread_;
    std::atomic<bool> is_running_;
    std::atomic<int> total_events_;
    std::atomic<int> vfs_events_;
    std::atomic<int> syscall_events_;
    std::atomic<int> filtered_events_;
    std::atomic<int> relevant_events_;
    std::vector<std::string> relevant_paths_;
    
    // 智能路径过滤器
    bool isRelevantPath(const char* path) {
        if (!path || strlen(path) < 3) return false;
        
        // 排除系统路径
        if (strncmp(path, "/proc/", 6) == 0) return false;
        if (strncmp(path, "/sys/", 5) == 0) return false;
        if (strncmp(path, "/dev/", 5) == 0) return false;
        
        // 排除临时和缓存文件
        if (strstr(path, "/.cache/") != nullptr) return false;
        if (strstr(path, "/tmp/") != nullptr && 
            strstr(path, "fexit_") == nullptr) return false;  // 允许我们的测试文件
        
        // 排除特定文件类型
        if (strstr(path, ".tmp") != nullptr) return false;
        if (strstr(path, ".swp") != nullptr) return false;
        if (strstr(path, ".log") != nullptr) return false;
        
        // 关注用户数据和测试文件
        if (strncmp(path, "/home/", 6) == 0) return true;
        if (strncmp(path, "/tmp/fexit_", 11) == 0) return true;  // 我们的测试文件
        if (strncmp(path, "/var/", 5) == 0) return true;
        if (strncmp(path, "/opt/", 5) == 0) return true;
        
        return false;  // 默认过滤掉
    }
    
    void performFileSystemTest() {
        std::cout << "\n📝 Performing filesystem structure test..." << std::endl;
        
        // 1. 创建用户数据文件
        std::cout << "1. 🔍 Creating user data files..." << std::endl;
        std::vector<std::string> user_files = {
            "/tmp/fexit_user_document.txt",
            "/tmp/fexit_important_data.csv",
            "/tmp/fexit_config.conf"
        };
        
        for (const auto& filepath : user_files) {
            std::ofstream file(filepath);
            file << "Important user content for " << filepath << std::endl;
            file.close();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 2. 创建目录结构
        std::cout << "2. 🔍 Creating directory structure..." << std::endl;
        mkdir("/tmp/fexit_project", 0755);
        mkdir("/tmp/fexit_project/src", 0755);
        mkdir("/tmp/fexit_project/docs", 0755);
        
        // 3. 在目录中创建文件
        std::cout << "3. 🔍 Creating files in directories..." << std::endl;
        std::ofstream("/tmp/fexit_project/README.md") << "# Project Documentation" << std::endl;
        std::ofstream("/tmp/fexit_project/src/main.cpp") << "int main() { return 0; }" << std::endl;
        
        // 4. 重命名操作
        std::cout << "4. 🔍 Renaming files..." << std::endl;
        rename("/tmp/fexit_user_document.txt", "/tmp/fexit_renamed_document.txt");
        
        // 5. 删除操作
        std::cout << "5. 🔍 Deleting files..." << std::endl;
        unlink("/tmp/fexit_important_data.csv");
        unlink("/tmp/fexit_config.conf");
        unlink("/tmp/fexit_renamed_document.txt");
        unlink("/tmp/fexit_project/README.md");
        unlink("/tmp/fexit_project/src/main.cpp");
        
        // 清理目录
        rmdir("/tmp/fexit_project/src");
        rmdir("/tmp/fexit_project/docs");
        rmdir("/tmp/fexit_project");
        
        std::cout << "📁 Filesystem test operations completed" << std::endl;
    }
    
    void pollRingBuffer() {
        while (is_running_) {
            ring_buffer__poll(ring_buf_, 100);
        }
    }
    
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
        auto *test = static_cast<FexitFilteredTest*>(ctx);
        
        if (data_sz == sizeof(vfs_event) || data_sz == 4120) {
            const vfs_event *event = static_cast<const vfs_event*>(data);
            
            test->total_events_++;
            
            // 区分事件来源
            const char* source_type = "";
            bool has_path = false;
            
            switch(event->source_type) {
                case VFS_SOURCE:
                    source_type = "[VFS-STRUCT]";
                    test->vfs_events_++;
                    break;
                case SYSCALL_SOURCE:
                    source_type = "[SYS-PATH]";
                    test->syscall_events_++;
                    has_path = (event->cookie == 1);
                    break;
                default:
                    source_type = "[UNK]";
                    break;
            }
            
            // 应用智能过滤
            bool is_relevant = false;
            if (has_path && strlen(event->path) > 5) {
                is_relevant = test->isRelevantPath(event->path);
                if (is_relevant) {
                    test->relevant_events_++;
                    if (test->relevant_paths_.size() < 20) {
                        test->relevant_paths_.push_back(std::string(event->path));
                    }
                } else {
                    test->filtered_events_++;
                }
            } else if (event->source_type == VFS_SOURCE) {
                // VFS事件通常都是相关的结构变化
                is_relevant = true;
                test->relevant_events_++;
            }
            
            // 只打印相关事件的前几个
            static std::atomic<int> relevant_print_count(0);
            if (is_relevant && relevant_print_count.load() < 10) {
                relevant_print_count++;
                
                std::cout << source_type << " PID:" << event->pid 
                         << " Action:" << (int)event->action;
                         
                if (has_path && strlen(event->path) > 8) {
                    std::cout << " 🎯PATH:" << event->path;
                } else {
                    std::cout << " Info:" << event->path;
                }
                std::cout << std::endl;
            }
        }
        
        return 0;
    }
    
    void printFilteredResults(std::chrono::milliseconds duration) {
        std::cout << "\n🎊 === Filtered Fexit Test Results ===" << std::endl;
        std::cout << "⏱️ Test duration: " << duration.count() << " ms" << std::endl;
        std::cout << "📊 Total events captured: " << total_events_.load() << std::endl;
        std::cout << "📊 VFS structure events: " << vfs_events_.load() << std::endl;
        std::cout << "📊 Syscall events: " << syscall_events_.load() << std::endl;
        std::cout << "🎯 Relevant events: " << relevant_events_.load() << std::endl;
        std::cout << "🚫 Filtered out events: " << filtered_events_.load() << std::endl;
        
        // 计算过滤效果
        double filter_efficiency = total_events_.load() > 0 ? 
                                  (double)filtered_events_.load() / total_events_.load() * 100 : 0;
        double relevance_ratio = total_events_.load() > 0 ? 
                                (double)relevant_events_.load() / total_events_.load() * 100 : 0;
        
        std::cout << "📈 Filter efficiency: " << filter_efficiency << "% (noise filtered)" << std::endl;
        std::cout << "📈 Relevance ratio: " << relevance_ratio << "% (useful events)" << std::endl;
        
        // 显示相关路径样本
        if (!relevant_paths_.empty()) {
            std::cout << "\n🎯 Relevant paths captured:" << std::endl;
            for (size_t i = 0; i < std::min((size_t)10, relevant_paths_.size()); i++) {
                std::cout << "   " << (i+1) << ". " << relevant_paths_[i] << std::endl;
            }
        }
        
        // 评估结果
        std::cout << "\n✅ === Filtering Assessment ===" << std::endl;
        bool good_filtering = filter_efficiency > 50;  // 过滤掉超过50%的噪音
        bool good_relevance = relevance_ratio > 20;    // 至少20%的事件是相关的
        bool manageable_volume = relevant_events_.load() < 1000;  // 相关事件数量可管理
        
        std::cout << "✅ Noise filtering: " << (good_filtering ? "EXCELLENT" : "MODERATE") 
                  << " (" << filter_efficiency << "%)" << std::endl;
        std::cout << "✅ Event relevance: " << (good_relevance ? "GOOD" : "NEEDS_TUNING") 
                  << " (" << relevance_ratio << "%)" << std::endl;
        std::cout << "✅ Event volume: " << (manageable_volume ? "MANAGEABLE" : "HIGH") 
                  << " (" << relevant_events_.load() << " events)" << std::endl;
        
        if (good_filtering && good_relevance && manageable_volume) {
            std::cout << "\n🎉 Filtered Monitoring: OPTIMIZED!" << std::endl;
            std::cout << "🚀 Ready for production with intelligent filtering!" << std::endl;
        } else {
            std::cout << "\n⚠️ Filtering may need further tuning" << std::endl;
        }
    }
    
    void cleanup() {
        is_running_ = false;
        
        if (polling_thread_.joinable()) {
            polling_thread_.join();
        }
        
        if (ring_buf_) {
            ring_buffer__free(ring_buf_);
            ring_buf_ = nullptr;
        }
        
        for (auto link : fexit_links_) {
            bpf_link__destroy(link);
        }
        fexit_links_.clear();
        
        if (obj_) {
            bpf_object__close(obj_);
            obj_ = nullptr;
        }
    }
};

int main() {
    std::cout << "🔥 Fexit Filtered Filesystem Monitor Test" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "目标：验证智能过滤的文件系统监控" << std::endl;
    
    FexitFilteredTest test;
    
    if (!test.initialize()) {
        std::cerr << "❌ Failed to initialize test" << std::endl;
        return 1;
    }
    
    test.startFilteredTest();
    
    std::cout << "\n🚀 Filtered fexit test completed!" << std::endl;
    return 0;
} 