#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "include/ebpf_common.h"

// Include the generated eBPF bytecode
#include "fentry_simple_vfs_bytecode.h"

class FentryPerformanceTest {
public:
    FentryPerformanceTest() : obj_(nullptr), ring_buf_(nullptr), event_count_(0) {}
    
    ~FentryPerformanceTest() {
        cleanup();
    }
    
    bool initialize() {
        std::cout << "Initializing fentry performance test..." << std::endl;
        
        // Load eBPF program
        struct bpf_object_open_opts opts = {};
        opts.sz = sizeof(struct bpf_object_open_opts);
        
        obj_ = bpf_object__open_mem(fentry_simple_vfs_o, fentry_simple_vfs_o_len, &opts);
        if (!obj_) {
            std::cerr << "Failed to open eBPF object" << std::endl;
            return false;
        }
        
        // Load the program into kernel
        if (bpf_object__load(obj_) != 0) {
            std::cerr << "Failed to load eBPF program" << std::endl;
            return false;
        }
        
        std::cout << "Fentry eBPF program loaded successfully" << std::endl;
        
        // Attach fentry programs
        return attachFentryPrograms();
    }
    
    bool attachFentryPrograms() {
        std::cout << "Attaching fentry programs..." << std::endl;
        
        // List of fentry programs to attach
        const char* fentry_programs[] = {
            "fentry_vfs_create",
            "fentry_vfs_mkdir", 
            "fentry_vfs_unlink",
            "fentry_vfs_rmdir",
            "fentry_vfs_rename"
        };
        
        int attached_count = 0;
        for (const char* prog_name : fentry_programs) {
            struct bpf_program *prog = bpf_object__find_program_by_name(obj_, prog_name);
            if (prog) {
                struct bpf_link *link = bpf_program__attach(prog);
                if (link) {
                    fentry_links_.push_back(link);
                    attached_count++;
                    std::cout << "Fentry: Attached to " << prog_name << std::endl;
                } else {
                    std::cerr << "Fentry: Failed to attach " << prog_name << std::endl;
                }
            } else {
                std::cerr << "Fentry: Program " << prog_name << " not found" << std::endl;
            }
        }
        
        std::cout << "Fentry: Attached " << attached_count << "/" << 5 << " programs" << std::endl;
        
        // Setup ring buffer
        return setupRingBuffer();
    }
    
    bool setupRingBuffer() {
        // Find the ring buffer map
        struct bpf_map *map = bpf_object__find_map_by_name(obj_, "fentry_simple_events");
        if (!map) {
            std::cerr << "Failed to find ring buffer map" << std::endl;
            return false;
        }
        
        // Create ring buffer
        ring_buf_ = ring_buffer__new(bpf_map__fd(map), handleRingBufferEvent, this, nullptr);
        if (!ring_buf_) {
            std::cerr << "Failed to create ring buffer" << std::endl;
            return false;
        }
        
        std::cout << "Ring buffer setup successful" << std::endl;
        return true;
    }
    
    void startPerformanceTest() {
        std::cout << "\n=== Starting Fentry Performance Test ===" << std::endl;
        
        // Start ring buffer polling
        is_running_ = true;
        polling_thread_ = std::thread(&FentryPerformanceTest::pollRingBuffer, this);
        
        // Wait for initialization
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Perform intensive file operations
        performIntensiveFileOps();
        
        // Wait for events to be processed
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // Stop monitoring
        is_running_ = false;
        if (polling_thread_.joinable()) {
            polling_thread_.join();
        }
        
        // Print results
        std::cout << "\n=== Fentry Performance Results ===" << std::endl;
        std::cout << "Total events captured: " << event_count_.load() << std::endl;
        std::cout << "Test duration: " << duration.count() << " ms" << std::endl;
        std::cout << "Events per second: " << (event_count_.load() * 1000.0 / duration.count()) << std::endl;
    }
    
private:
    struct bpf_object *obj_;
    std::vector<struct bpf_link*> fentry_links_;
    struct ring_buffer *ring_buf_;
    std::thread polling_thread_;
    std::atomic<bool> is_running_;
    std::atomic<int> event_count_;
    
    void performIntensiveFileOps() {
        std::cout << "Performing intensive file operations..." << std::endl;
        
        // Create and delete many files to trigger VFS events
        for (int i = 0; i < 100; i++) {
            std::string filename = "/tmp/fentry_test_" + std::to_string(i);
            
            // Create file
            std::ofstream file(filename);
            file << "test data " << i << std::endl;
            file.close();
            
            // Create directory
            std::string dirname = "/tmp/fentry_dir_" + std::to_string(i);
            mkdir(dirname.c_str(), 0755);
            
            // Delete file
            unlink(filename.c_str());
            
            // Delete directory
            rmdir(dirname.c_str());
            
            // Small delay to avoid overwhelming the system
            if (i % 10 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        
        std::cout << "File operations completed" << std::endl;
    }
    
    void pollRingBuffer() {
        while (is_running_) {
            ring_buffer__poll(ring_buf_, 100); // 100ms timeout
        }
    }
    
    static int handleRingBufferEvent(void *ctx, void *data, size_t data_sz) {
        auto *test = static_cast<FentryPerformanceTest*>(ctx);
        
        if (data_sz == sizeof(vfs_event) || data_sz == 4120) {
            const vfs_event *event = static_cast<const vfs_event*>(data);
            test->event_count_++;
            
            // Print some events for verification
            if (test->event_count_.load() <= 10) {
                std::cout << "[FENTRY] PID:" << event->pid 
                         << " Action:" << (int)event->action 
                         << " Path:" << event->path << std::endl;
            }
        }
        
        return 0;
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
        
        for (auto link : fentry_links_) {
            bpf_link__destroy(link);
        }
        fentry_links_.clear();
        
        if (obj_) {
            bpf_object__close(obj_);
            obj_ = nullptr;
        }
    }
};

int main() {
    std::cout << "Fentry VFS Monitoring Performance Test" << std::endl;
    std::cout << "======================================" << std::endl;
    
    FentryPerformanceTest test;
    
    if (!test.initialize()) {
        std::cerr << "Failed to initialize test" << std::endl;
        return 1;
    }
    
    test.startPerformanceTest();
    
    std::cout << "\nFentry performance test completed!" << std::endl;
    return 0;
} 