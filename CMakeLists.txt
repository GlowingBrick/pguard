cmake_minimum_required(VERSION 3.5)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)  # 默认使用 Release 模式
endif()

# 从环境变量获取ANDROID_NDK路径
if(NOT DEFINED ENV{ANDROID_NDK})
    message(FATAL_ERROR "ANDROID_NDK environment variable is not set")
endif()

set(ANDROID_NDK $ENV{ANDROID_NDK})
# 设置项目名称
project(pguard)

# 设置交叉编译工具链
set(CMAKE_CXX_COMPILER ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++)

# 添加可执行文件
add_executable(pguard
    main.cpp
)

# 设置编译选项
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-rtti")

# 设置链接选项
#target_link_options(pguard PRIVATE -static-libstdc++)

# 链接库
target_link_libraries(pguard PRIVATE log)

target_link_options(pguard PRIVATE
    "-static-libstdc++"  # 静态链接 libc++
)

# 查找zip程序
find_program(ZIP_EXECUTABLE zip)

if(ZIP_EXECUTABLE)
    # 添加自定义目标，用于打包文件
    add_custom_target(package ALL
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/module.prop ${CMAKE_CURRENT_BINARY_DIR}/module.prop
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/service.sh ${CMAKE_CURRENT_BINARY_DIR}/service.sh
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pguard> ${CMAKE_CURRENT_BINARY_DIR}/pguard
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/config.json ${CMAKE_CURRENT_BINARY_DIR}/config.json
        COMMAND ${ZIP_EXECUTABLE} -j ${CMAKE_CURRENT_BINARY_DIR}/pguard_package.zip
            ${CMAKE_CURRENT_BINARY_DIR}/module.prop
            ${CMAKE_CURRENT_BINARY_DIR}/service.sh
            ${CMAKE_CURRENT_BINARY_DIR}/pguard
            ${CMAKE_CURRENT_BINARY_DIR}/config.json
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS pguard
        COMMENT "Packaging module.prop, service.sh and pguard into pguard-package.zip"
    )
else()
    message(WARNING "zip program not found, packaging target will not be available")
endif()
