cmake_minimum_required(VERSION 3.16)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(spdlog REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)

# Check for clang compiler for eBPF programs
find_program(CLANG_EXECUTABLE clang)
if(NOT CLANG_EXECUTABLE)
    message(WARNING "clang not found, eBPF programs will not be compiled")
    return()
endif()

# eBPF program compilation function
function(compile_ebpf_program target_name source_file)
    set(output_file "${CMAKE_CURRENT_BINARY_DIR}/${target_name}.o")
    set(header_file "${CMAKE_CURRENT_BINARY_DIR}/${target_name}_bytecode.h")
    
    # Compile eBPF program to object file
    add_custom_command(
        OUTPUT ${output_file}
        COMMAND ${CLANG_EXECUTABLE} 
            -target bpf 
            -D__TARGET_ARCH_x86
            -O2 
            -g 
            -c ${source_file} 
            -o ${output_file}
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            -I/usr/include
            -I/usr/include/x86_64-linux-gnu
        DEPENDS ${source_file}
        COMMENT "Compiling eBPF program ${target_name}"
    )
    
    # Convert object file to C header with byte array
    add_custom_command(
        OUTPUT ${header_file}
        COMMAND xxd -i ${target_name}.o > ${header_file}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${output_file}
        COMMENT "Converting eBPF bytecode to header ${target_name}"
    )
    
    add_custom_target(${target_name}_bytecode DEPENDS ${header_file})
endfunction()

# Compile eBPF programs
compile_ebpf_program(vfs_monitor ${CMAKE_CURRENT_SOURCE_DIR}/programs/vfs_monitor.c)
compile_ebpf_program(vfs_monitor_enhanced ${CMAKE_CURRENT_SOURCE_DIR}/programs/vfs_monitor_enhanced.c)
compile_ebpf_program(mmap_monitor ${CMAKE_CURRENT_SOURCE_DIR}/programs/mmap_monitor.c)

# Create userspace library
add_library(ebpf_event_source STATIC
    userspace/event_manager.cpp
    userspace/ebpf_program_loader.cpp
    userspace/event_cache_merger.cpp
    userspace/netlink_sender.cpp
)

# Create enhanced eBPF library (simplified version)
add_library(ebpf_enhanced STATIC
    enhanced/simple_enhanced_manager.cpp
    enhanced/enhanced_event_manager.cpp
    enhanced/event_deduplicator.cpp
    enhanced/vfs_layer_monitor.cpp
    enhanced/memory_map_monitor.cpp
    enhanced/performance_monitor.cpp
    userspace/event_manager.cpp
    userspace/ebpf_program_loader.cpp
    userspace/event_cache_merger.cpp
    userspace/netlink_sender.cpp
)

target_include_directories(ebpf_event_source PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBNL_INCLUDE_DIRS}
)

target_link_libraries(ebpf_event_source
    ${LIBBPF_LIBRARIES}
    ${LIBNL_LIBRARIES}
    spdlog::spdlog
)

target_compile_definitions(ebpf_event_source PRIVATE
    ${LIBBPF_CFLAGS_OTHER}
)

# Configure enhanced library
target_include_directories(ebpf_enhanced PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBNL_INCLUDE_DIRS}
)

target_link_libraries(ebpf_enhanced
    ${LIBBPF_LIBRARIES}
    ${LIBNL_LIBRARIES}
    spdlog::spdlog
)

target_compile_definitions(ebpf_enhanced PRIVATE
    ${LIBBPF_CFLAGS_OTHER}
)

# Ensure eBPF bytecode is generated before library compilation
add_dependencies(ebpf_event_source vfs_monitor_bytecode)
add_dependencies(ebpf_enhanced vfs_monitor_enhanced_bytecode mmap_monitor_bytecode)

# Create test executables
add_executable(test_ebpf test_ebpf.cpp)
target_link_libraries(test_ebpf 
    ebpf_event_source
    spdlog::spdlog
)
target_include_directories(test_ebpf PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
)

add_executable(test_simple_enhanced test_simple_enhanced.cpp)
target_link_libraries(test_simple_enhanced 
    ebpf_enhanced
    spdlog::spdlog
)
target_include_directories(test_simple_enhanced PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
)

# Test for enhanced event manager
add_executable(test_enhanced_event_manager test_enhanced_event_manager.cpp)
target_link_libraries(test_enhanced_event_manager 
    ebpf_enhanced
    spdlog::spdlog
)
target_include_directories(test_enhanced_event_manager PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
)

# Complete monitoring test with file operations
add_executable(test_complete_monitoring test_complete_monitoring.cpp)
target_link_libraries(test_complete_monitoring 
    ebpf_enhanced
    spdlog::spdlog
)
target_include_directories(test_complete_monitoring PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
)

# Debug struct size utility
add_executable(debug_struct_size debug_struct_size.cpp)
target_include_directories(debug_struct_size PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
) 