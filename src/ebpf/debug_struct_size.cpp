#include <iostream>
#include "include/ebpf_common.h"

int main() {
    std::cout << "=== Struct Size Debug ===\n";
    std::cout << "sizeof(vfs_event): " << sizeof(vfs_event) << " bytes\n";
    std::cout << "Expected by eBPF: 4120 bytes\n";
    
    std::cout << "\n=== Field Analysis ===\n";
    std::cout << "pid (uint32): " << sizeof(uint32_t) << " bytes\n";
    std::cout << "uid (uint32): " << sizeof(uint32_t) << " bytes\n";
    std::cout << "action (uint8): " << sizeof(uint8_t) << " bytes\n";
    std::cout << "cookie (uint32): " << sizeof(uint32_t) << " bytes\n";
    std::cout << "major (uint16): " << sizeof(uint16_t) << " bytes\n";
    std::cout << "minor (uint8): " << sizeof(uint8_t) << " bytes\n";
    std::cout << "timestamp (uint64): " << sizeof(uint64_t) << " bytes\n";
    std::cout << "source_type (uint32): " << sizeof(uint32_t) << " bytes\n";
    std::cout << "path (char[4096]): " << MAX_PATH_LEN << " bytes\n";
    
    uint32_t total_calculated = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + 
                               sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + 
                               sizeof(uint64_t) + sizeof(uint32_t) + MAX_PATH_LEN;
    std::cout << "Calculated total: " << total_calculated << " bytes\n";
    
    return 0;
} 