cmake_minimum_required (VERSION 3.0)
project (emp-aby)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(NAME "emp-aby")

# Debug
set(CMAKE_BUILD_TYPE Release)
# add_compile_options(-g -O0)
set(CMAKE_OSX_SYSROOT /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk)

# 设置 EMP_TOOL_DIR 为相对路径
set(EMP_TOOL_DIR ${CMAKE_SOURCE_DIR}/emp-tool)
include_directories(${EMP_TOOL_DIR})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    # On macOS
    include_directories(/opt/homebrew/opt/openssl/include)
else()
    # On Linux
    include_directories(${CMAKE_SOURCE_DIR}/external/openssl/include)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Enabling AddressSanitizer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}-O3 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wno-sign-compare")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS} -O3 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -DMATHBACKEND=4")

if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBS_USE_LIBUV -DLIBS_USE_OPENSSL")
endif()

# 设置 emp-tool 的相对路径
set(CMAKE_FOLDER ${CMAKE_SOURCE_DIR}/emp-tool)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

# 查找 OpenFHE
find_package(OpenFHE REQUIRED)

# 添加子目录
add_subdirectory(external/mcl)
add_subdirectory(libelgl)

# 包含目录
include_directories(external/mcl/include)
include_directories(libelgl)
include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)

# 链接目录
link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})

# Handle filesystem library based on OS
if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    # On macOS, filesystem is part of the standard library
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
else()
    # On Linux, we need to link against stdc++fs
    link_libraries(stdc++fs)
endif()

if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries(${OpenFHE_STATIC_LIBRARIES})
else()
    set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
    link_libraries(${OpenFHE_SHARED_LIBRARIES})
endif()

# 查找 emp-ot
find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

# 安装配置
install(FILES cmake/emp-aby-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-aby DESTINATION include/)

# 启用测试
ENABLE_TESTING()
# ADD_SUBDIRECTORY(test)
# ADD_SUBDIRECTORY(testLLM)
ADD_SUBDIRECTORY(testLYL)
# ADD_SUBDIRECTORY(testProof)