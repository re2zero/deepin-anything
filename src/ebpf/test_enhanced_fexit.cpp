#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <vector>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include "enhanced/enhanced_event_manager.h"

class EnhancedFexitTest {
public:
    EnhancedFexitTest() : event_count_(0), vfs_events_(0), syscall_events_(0) {}
    
    void run() {
        std::cout << "🔥 Enhanced Event Manager with Fexit Integration Test" << std::endl;
        std::cout << "=================================================" << std::endl;
        std::cout << "目标：验证集成了fexit的增强事件管理器" << std::endl;
        
        ebpf::EnhancedEventManager manager;
        
        // 初始化管理器
        if (!manager.initialize()) {
            std::cerr << "❌ Failed to initialize Enhanced Event Manager" << std::endl;
            return;
        }
        
        // 打印能力和策略信息
        printCapabilitiesAndStrategy(manager);
        
        // 设置事件处理器
        manager.setEventHandler([this](const vfs_event& event) {
            handleEvent(event);
        });
        
        // 开始监控
        if (!manager.startMonitoring()) {
            std::cerr << "❌ Failed to start monitoring" << std::endl;
            return;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 执行综合文件操作测试
        performComprehensiveFileOperations();
        
        // 监控5秒
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // 停止监控
        manager.stopMonitoring();
        
        // 打印综合结果
        printIntegratedResults(manager, duration);
    }
    
private:
    std::atomic<int> event_count_;
    std::atomic<int> vfs_events_;
    std::atomic<int> syscall_events_;
    std::vector<std::string> sample_paths_;
    
    void printCapabilitiesAndStrategy(const ebpf::EnhancedEventManager& manager) {
        const auto& caps = manager.getCapabilities();
        auto strategy = manager.getCurrentStrategy();
        
        std::cout << "\n📋 === System Capabilities ===" << std::endl;
        std::cout << "🚀 Supports Fexit: " << (caps.supports_fexit ? "✅" : "❌") << std::endl;
        std::cout << "🔧 VFS Tracepoints: " << (caps.vfs_tracepoints_available ? "✅" : "❌") << std::endl;
        std::cout << "🔧 VFS Kprobe: " << (caps.vfs_kprobe_available ? "✅" : "❌") << std::endl;
        std::cout << "🔧 Syscall Tracepoints: " << (caps.syscall_tracepoints_available ? "✅" : "❌") << std::endl;
        std::cout << "🔐 CAP_BPF: " << (caps.has_cap_bpf ? "✅" : "❌") << std::endl;
        std::cout << "🔐 CAP_SYS_ADMIN: " << (caps.has_cap_sys_admin ? "✅" : "❌") << std::endl;
        std::cout << "💻 Kernel: " << caps.kernel_version_major << "." << caps.kernel_version_minor << std::endl;
        
        std::cout << "\n🎯 === Selected Strategy ===" << std::endl;
        const char* strategy_name = "";
        switch(strategy) {
            case ebpf::EnhancedEventManager::FEXIT_PRODUCTION:
                strategy_name = "🚀 FEXIT_PRODUCTION (Optimal!)";
                break;
            case ebpf::EnhancedEventManager::FULL_COVERAGE:
                strategy_name = "🔧 FULL_COVERAGE (Traditional)";
                break;
            case ebpf::EnhancedEventManager::SYSCALL_ONLY:
                strategy_name = "⚠️ SYSCALL_ONLY (Limited)";
                break;
            case ebpf::EnhancedEventManager::KERNEL_MODULE:
                strategy_name = "🔙 KERNEL_MODULE (Fallback)";
                break;
        }
        std::cout << "Strategy: " << strategy_name << std::endl;
    }
    
    void handleEvent(const vfs_event& event) {
        event_count_++;
        
        // 区分事件来源
        switch(event.source_type) {
            case 1: // VFS_SOURCE
                vfs_events_++;
                break;
            case 0: // SYSCALL_SOURCE
                syscall_events_++;
                // 只收集看起来像真实路径的样本
                if (strlen(event.path) > 10 && 
                    strncmp(event.path, "/tmp/enhanced_", 14) == 0 &&
                    sample_paths_.size() < 10) {
                    sample_paths_.push_back(std::string(event.path));
                }
                break;
        }
        
        // 只打印前几个相关事件
        static std::atomic<int> print_count(0);
        if (print_count.load() < 8 && 
            (strstr(event.path, "enhanced_") != nullptr || event.source_type == 1)) {
            print_count++;
            
            const char* source_name = (event.source_type == 1) ? "[VFS-FEXIT]" : "[SYS-FEXIT]";
            std::cout << source_name << " PID:" << event.pid 
                     << " Action:" << (int)event.action;
                     
            if (strlen(event.path) > 15) {
                std::cout << " 🎯PATH:" << event.path;
            } else {
                std::cout << " Info:" << event.path;
            }
            std::cout << std::endl;
        }
    }
    
    void performComprehensiveFileOperations() {
        std::cout << "\n📝 Performing comprehensive file operations test..." << std::endl;
        
        // 1. 创建测试文件
        std::cout << "1. 🔍 Creating test files..." << std::endl;
        std::vector<std::string> test_files = {
            "/tmp/enhanced_test_document.txt",
            "/tmp/enhanced_config.json",
            "/tmp/enhanced_data.csv"
        };
        
        for (const auto& filepath : test_files) {
            std::ofstream file(filepath);
            file << "Enhanced Event Manager test content for " << filepath << std::endl;
            file.close();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 2. 创建目录结构
        std::cout << "2. 🔍 Creating directory structure..." << std::endl;
        mkdir("/tmp/enhanced_project", 0755);
        mkdir("/tmp/enhanced_project/src", 0755);
        mkdir("/tmp/enhanced_project/config", 0755);
        
        // 3. 在目录中创建文件
        std::cout << "3. 🔍 Creating files in directories..." << std::endl;
        std::ofstream("/tmp/enhanced_project/README.md") << "# Enhanced Project" << std::endl;
        std::ofstream("/tmp/enhanced_project/src/main.cpp") << "// Enhanced main file" << std::endl;
        std::ofstream("/tmp/enhanced_project/config/settings.conf") << "enhanced=true" << std::endl;
        
        // 4. 文件重命名
        std::cout << "4. 🔍 Renaming files..." << std::endl;
        rename("/tmp/enhanced_test_document.txt", "/tmp/enhanced_renamed_document.txt");
        rename("/tmp/enhanced_config.json", "/tmp/enhanced_settings.json");
        
        // 5. 批量创建和删除（测试性能）
        std::cout << "5. 🔍 Batch operations..." << std::endl;
        for (int i = 0; i < 20; i++) {
            std::string filepath = "/tmp/enhanced_batch_" + std::to_string(i) + ".tmp";
            std::ofstream file(filepath);
            file << "Batch test " << i << std::endl;
            file.close();
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        // 删除批量文件
        for (int i = 0; i < 20; i++) {
            std::string filepath = "/tmp/enhanced_batch_" + std::to_string(i) + ".tmp";
            unlink(filepath.c_str());
        }
        
        // 6. 清理测试文件
        std::cout << "6. 🔍 Cleaning up..." << std::endl;
        unlink("/tmp/enhanced_renamed_document.txt");
        unlink("/tmp/enhanced_settings.json");
        unlink("/tmp/enhanced_data.csv");
        unlink("/tmp/enhanced_project/README.md");
        unlink("/tmp/enhanced_project/src/main.cpp");
        unlink("/tmp/enhanced_project/config/settings.conf");
        
        rmdir("/tmp/enhanced_project/src");
        rmdir("/tmp/enhanced_project/config");
        rmdir("/tmp/enhanced_project");
        
        std::cout << "📁 Comprehensive file operations completed" << std::endl;
    }
    
    void printIntegratedResults(const ebpf::EnhancedEventManager& manager, 
                               std::chrono::milliseconds duration) {
        std::cout << "\n🎊 === Enhanced Fexit Integration Results ===" << std::endl;
        std::cout << "⏱️ Test duration: " << duration.count() << " ms" << std::endl;
        std::cout << "📊 Total events processed: " << event_count_.load() << std::endl;
        std::cout << "📊 VFS events: " << vfs_events_.load() << std::endl;
        std::cout << "📊 Syscall events: " << syscall_events_.load() << std::endl;
        
        // 计算事件处理率
        double events_per_second = duration.count() > 0 ? 
                                  (double)event_count_.load() / (duration.count() / 1000.0) : 0;
        std::cout << "⚡ Events per second: " << events_per_second << std::endl;
        
        // 显示性能统计
        std::cout << "\n📈 === Performance Stats ===" << std::endl;
        std::cout << "Manager EPS: " << manager.getEventsPerSecond() << std::endl;
        
        // 显示捕获的路径样本
        if (!sample_paths_.empty()) {
            std::cout << "\n🎯 Sample paths captured:" << std::endl;
            for (size_t i = 0; i < std::min((size_t)8, sample_paths_.size()); i++) {
                std::cout << "   " << (i+1) << ". " << sample_paths_[i] << std::endl;
            }
        }
        
        // 评估整体性能
        std::cout << "\n✅ === Integration Assessment ===" << std::endl;
        bool good_performance = events_per_second > 100;
        bool captured_paths = !sample_paths_.empty();
        bool strategy_optimal = (manager.getCurrentStrategy() == ebpf::EnhancedEventManager::FEXIT_PRODUCTION);
        
        std::cout << "✅ Performance: " << (good_performance ? "EXCELLENT" : "MODERATE") 
                  << " (" << events_per_second << " eps)" << std::endl;
        std::cout << "✅ Path capture: " << (captured_paths ? "SUCCESS" : "NEEDS_CHECK") << std::endl;
        std::cout << "✅ Strategy: " << (strategy_optimal ? "OPTIMAL (Fexit)" : "FALLBACK") << std::endl;
        
        if (good_performance && captured_paths && strategy_optimal) {
            std::cout << "\n🎉 Enhanced Fexit Integration: SUCCESS!" << std::endl;
            std::cout << "🚀 Production-ready with optimal fexit monitoring!" << std::endl;
        } else if (good_performance && captured_paths) {
            std::cout << "\n✅ Enhanced Integration: WORKING!" << std::endl;
            std::cout << "📊 Using fallback strategy but performing well" << std::endl;
        } else {
            std::cout << "\n⚠️ Integration needs review" << std::endl;
        }
    }
};

int main() {
    EnhancedFexitTest test;
    test.run();
    return 0;
} 