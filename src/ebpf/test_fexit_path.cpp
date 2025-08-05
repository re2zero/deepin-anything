#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "include/ebpf_common.h"

// Include the generated eBPF bytecode
#include "fexit_with_path_bytecode.h"

class FexitPathTest {
public:
    FexitPathTest() : obj_(nullptr), ring_buf_(nullptr), 
                      vfs_events_(0), syscall_events_(0), path_events_(0) {}
    
    ~FexitPathTest() {
        cleanup();
    }
    
    bool initialize() {
        std::cout << "🚀 Initializing Fexit Path Monitor..." << std::endl;
        
        // Load eBPF program
        struct bpf_object_open_opts opts = {};
        opts.sz = sizeof(struct bpf_object_open_opts);
        
        obj_ = bpf_object__open_mem(fexit_with_path_o, 
                                   fexit_with_path_o_len, &opts);
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
        std::cout << "🔗 Attaching fexit programs..." << std::endl;
        
        // List of fexit programs to attach
        const char* fexit_programs[] = {
            // VFS layer - 检测操作但无完整路径
            "fexit_vfs_create",
            "fexit_vfs_mkdir", 
            "fexit_vfs_unlink",
            "fexit_vfs_rmdir",
            "fexit_vfs_rename",
            // Syscall layer - 🔑 获取完整路径的关键
            "fexit_sys_openat2",
            "fexit_sys_open"
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
        struct bpf_map *map = bpf_object__find_map_by_name(obj_, "fexit_path_events");
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
    
    void startPathTest() {
        std::cout << "\n🎯 === Starting Fexit Path Extraction Test ===" << std::endl;
        std::cout << "目标：验证fexit可以获取完整文件路径" << std::endl;
        
        is_running_ = true;
        polling_thread_ = std::thread(&FexitPathTest::pollRingBuffer, this);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 执行特定的文件操作来测试路径提取
        performPathTestOperations();
        
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        is_running_ = false;
        if (polling_thread_.joinable()) {
            polling_thread_.join();
        }
        
        printPathResults(duration);
    }
    
private:
    struct bpf_object *obj_;
    std::vector<struct bpf_link*> fexit_links_;
    struct ring_buffer *ring_buf_;
    std::thread polling_thread_;
    std::atomic<bool> is_running_;
    std::atomic<int> vfs_events_;
    std::atomic<int> syscall_events_;
    std::atomic<int> path_events_;
    
    void performPathTestOperations() {
        std::cout << "\n📝 Performing path extraction test operations..." << std::endl;
        
        // 1. 文件创建操作 - 应该能获取完整路径
        std::cout << "1. 🔍 Testing file creation with path extraction..." << std::endl;
        std::string test_file = "/tmp/fexit_path_test.txt";
        std::ofstream file(test_file);
        file << "Testing fexit path extraction!" << std::endl;
        file.close();
        
        // 2. 目录创建操作 - 应该能获取完整路径
        std::cout << "2. 🔍 Testing directory creation with path extraction..." << std::endl;
        std::string test_dir = "/tmp/fexit_path_test_dir";
        mkdir(test_dir.c_str(), 0755);
        
        // 3. 文件重命名操作 - 应该能获取源和目标路径
        std::cout << "3. 🔍 Testing file rename with path extraction..." << std::endl;
        std::string renamed_file = "/tmp/fexit_path_test_renamed.txt";
        rename(test_file.c_str(), renamed_file.c_str());
        
        // 4. 文件删除操作 - 应该能获取完整路径
        std::cout << "4. 🔍 Testing file deletion with path extraction..." << std::endl;
        unlink(renamed_file.c_str());
        
        // 5. 目录删除操作
        std::cout << "5. 🔍 Testing directory deletion..." << std::endl;
        rmdir(test_dir.c_str());
        
        // 6. 创建一些具有不同路径的文件来展示路径多样性
        std::cout << "6. 🔍 Testing diverse file paths..." << std::endl;
        std::vector<std::string> test_files = {
            "/tmp/test_file_1.txt",
            "/tmp/sub_dir/test_file_2.txt",  // 需要先创建目录
            "/tmp/测试文件.txt",              // 中文文件名
            "/tmp/file with spaces.txt"      // 带空格的文件名
        };
        
        // 先创建子目录
        mkdir("/tmp/sub_dir", 0755);
        
        for (const auto& filepath : test_files) {
            std::ofstream f(filepath);
            f << "Content for " << filepath << std::endl;
            f.close();
            
            // 稍微延迟以便观察事件
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 清理测试文件
        for (const auto& filepath : test_files) {
            unlink(filepath.c_str());
        }
        rmdir("/tmp/sub_dir");
        
        std::cout << "📁 Path test operations completed" << std::endl;
    }
    
    void pollRingBuffer() {
        while (is_running_) {
            ring_buffer__poll(ring_buf_, 100);
        }
    }
    
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
        auto *test = static_cast<FexitPathTest*>(ctx);
        
        if (data_sz == sizeof(vfs_event) || data_sz == 4120) {
            const vfs_event *event = static_cast<const vfs_event*>(data);
            
            // 区分事件来源和类型
            const char* source_type = "";
            bool has_path = false;
            
            switch(event->source_type) {
                case VFS_SOURCE:
                    source_type = "[VFS]";
                    test->vfs_events_++;
                    break;
                case SYSCALL_SOURCE:
                    source_type = "[SYS-PATH]";
                    test->syscall_events_++;
                    has_path = (event->cookie == 1);  // cookie=1表示有路径
                    if (has_path) {
                        test->path_events_++;
                    }
                    break;
                default:
                    source_type = "[UNK]";
                    break;
            }
            
            // 只打印前20个事件以避免刷屏
            static std::atomic<int> print_count(0);
            if (print_count.load() < 20) {
                print_count++;
                
                std::cout << source_type << " PID:" << event->pid 
                         << " Action:" << (int)event->action;
                         
                if (has_path && strlen(event->path) > 16) {  // 看起来像真实路径
                    std::cout << " 🎯PATH:" << event->path;
                } else {
                    std::cout << " Info:" << event->path;
                }
                std::cout << std::endl;
            }
        }
        
        return 0;
    }
    
    void printPathResults(std::chrono::milliseconds duration) {
        std::cout << "\n🎊 === Fexit Path Extraction Results ===" << std::endl;
        std::cout << "⏱️ Test duration: " << duration.count() << " ms" << std::endl;
        std::cout << "📊 VFS events (no path): " << vfs_events_.load() << std::endl;
        std::cout << "📊 Syscall events (total): " << syscall_events_.load() << std::endl;
        std::cout << "🎯 Events with real paths: " << path_events_.load() << std::endl;
        
        if (path_events_.load() > 0) {
            std::cout << "\n✅ 路径提取验证成功！" << std::endl;
            std::cout << "✅ Fexit成功从syscall层获取了完整文件路径" << std::endl;
            std::cout << "✅ 双层监控策略有效：VFS检测 + Syscall路径" << std::endl;
        } else {
            std::cout << "\n⚠️ 未检测到路径事件，可能需要调试" << std::endl;
        }
        
        double path_ratio = syscall_events_.load() > 0 ? 
                           (double)path_events_.load() / syscall_events_.load() * 100 : 0;
        std::cout << "📈 路径提取成功率: " << path_ratio << "%" << std::endl;
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
    std::cout << "🔥 Fexit Path Extraction Test" << std::endl;
    std::cout << "==============================" << std::endl;
    std::cout << "目标：验证fexit能否获取完整文件路径" << std::endl;
    
    FexitPathTest test;
    
    if (!test.initialize()) {
        std::cerr << "❌ Failed to initialize test" << std::endl;
        return 1;
    }
    
    test.startPathTest();
    
    std::cout << "\n🚀 Fexit path extraction test completed!" << std::endl;
    return 0;
} 