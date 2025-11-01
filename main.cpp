#include <vector>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <fcntl.h>
#include <sys/stat.h>
#include "json.hpp"
#include <unistd.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif


using json = nlohmann::json;

// 定义日志标签
#define LOG_TAG "ProcessGuard"

// 跨平台日志宏定义
#ifdef __ANDROID__
    // Android 平台的日志定义
    #ifdef NDEBUG
        #define LOGV(...) ((void)0)
        #define LOGD(...) ((void)0)
        #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
        #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
        #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
    #else
        #define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
        #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
        #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
        #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
        #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
    #endif
    #define SHELL "/system/bin/sh"
#else
    // 非Android平台（Linux等）的日志定义
    #ifdef NDEBUG
        #define LOGV(...) ((void)0)
        #define LOGD(...) ((void)0)
        #define LOGI(fmt, ...) printf("[I/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
        #define LOGW(fmt, ...) printf("[W/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
        #define LOGE(fmt, ...) printf("[E/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
    #else
        #define LOGV(fmt, ...) printf("[V/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
        #define LOGD(fmt, ...) printf("[D/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
        #define LOGI(fmt, ...) printf("[I/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
        #define LOGW(fmt, ...) printf("[W/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
        #define LOGE(fmt, ...) printf("[E/" LOG_TAG "] " fmt "\n", ##__VA_ARGS__)
    #endif
    #define SHELL "/bin/sh"
#endif


// 分支预测优化宏
#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

class ProcessGuard {
private:
    std::string name;
    std::string cwd;
    std::string cmdline;
    bool guarding;
    std::vector<pid_t> pids;
    // 使用pidof命令获取进程PID
    std::vector<pid_t> getPidsByName(const std::string& processName) {
        std::vector<pid_t> result;
        char buffer[128];
        std::string command = "pidof " + processName;
        
        FILE* pipe = popen(command.c_str(), "r");
        if (UNLIKELY(!pipe)) {
            LOGE("Failed to execute pidof for %s", processName.c_str());
            return result;
        }
        
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            char* token = strtok(buffer, " ");
            while (token != nullptr) {
                pid_t pid = static_cast<pid_t>(atoi(token));
                if (pid > 0) {
                    result.push_back(pid);
                }
                token = strtok(nullptr, " ");
            }
        }
        
        pclose(pipe);
        return result;
    }

    // 启动进程并完全脱离
    void startProcess() {
        // 双重fork技术：创建守护进程
        pid_t pid = fork();
        if (UNLIKELY(pid < 0)) {
            LOGE("Fork failed for %s", name.c_str());
            return;
        }

        if (LIKELY(pid == 0)) { // 第一次fork的子进程
            // 创建新会话，成为进程组leader
            pid_t sid = setsid();
            if (UNLIKELY(sid < 0)) {
                LOGE("Failed to create new session for %s", name.c_str());
                exit(EXIT_FAILURE);
            }

            // 第二次fork确保不是会话leader
            pid_t grand_pid = fork();
            if (UNLIKELY(grand_pid < 0)) {
                LOGE("Second fork failed for %s", name.c_str());
                exit(EXIT_FAILURE);
            }

            if (grand_pid > 0) {
                // 第一级子进程退出，让孙子进程成为孤儿进程被init接管
                exit(EXIT_SUCCESS);
            }

            // 孙子进程（真正的守护进程）
            // 关闭所有打开的文件描述符
            for (int i = sysconf(_SC_OPEN_MAX); i >= 0; i--) {
                close(i);
            }

            // 重定向标准流到/dev/null
            int null_fd = open("/dev/null", O_RDWR);
            if (null_fd >= 0) {
                dup2(null_fd, STDIN_FILENO);
                dup2(null_fd, STDOUT_FILENO);
                dup2(null_fd, STDERR_FILENO);
                if (null_fd > STDERR_FILENO) close(null_fd);
            }

            // 设置工作目录
            if (!cwd.empty()) {
                if (UNLIKELY(chdir(cwd.c_str()) != 0)) {
                    // 使用系统日志而不是标准错误，因为已经重定向
                    LOGE("Failed to change directory to %s for %s", 
                         cwd.c_str(), name.c_str());
                }
            }

            // 设置umask
            umask(0);

            // 使用shell执行命令
            execl(SHELL, "sh", "-c", cmdline.c_str(), (char*)NULL);
            LOGI(cmdline.c_str());
            // 如果执行到这里，说明exec失败
            LOGE("Failed to execute shell command: %s for %s", 
                 cmdline.c_str(), name.c_str());
            exit(EXIT_FAILURE);
        } 
        else { // 父进程（守护程序）
            // 等待第一级子进程退出，避免僵尸进程
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
                LOGI("Started detached process %s", name.c_str());
            } else {
                LOGW("Failed to start detached process %s", name.c_str());
            }
        }
    }

public:
    ProcessGuard(const std::string& n, const std::string& wd, 
                 const std::string& cmd, bool autoRun)
        : name(n), cwd(wd), cmdline(cmd), guarding(autoRun)
    {
        LOGD("Created guard for %s (autorun: %s)", 
             n.c_str(), guarding ? "true" : "false");
    }
    
    void guard() {
        // 检查已知PID是否存活
        bool anyDead = false;
        for (auto it = pids.begin(); it != pids.end();) {
            if (UNLIKELY(kill(*it, 0) == -1)) {
                LOGI("Process %s (PID %d) terminated", name.c_str(), *it);
                it = pids.erase(it);
                anyDead = true;
            } else {
                ++it;
            }
        }
        
        // 如果已知PID列表为空，尝试获取新的PID
        if (UNLIKELY(pids.empty())) {
            auto newPids = getPidsByName(name);
            if (!newPids.empty()) {
                pids = newPids;
                LOGD("Found %zu instances of %s", pids.size(), name.c_str());
                
                if (UNLIKELY(!guarding)) {
                    guarding = true;
                    LOGI("Started guarding process: %s", name.c_str());
                }
                return;
            }
            
            // 如果没有找到进程且应该守护，则启动进程
            if (LIKELY(guarding)) {
                LOGI("Process %s not found, restarting...", name.c_str());
                startProcess();
            }
        } 
        else {
            if (UNLIKELY(anyDead)) {
                LOGD("Process %s: %zu instances remaining", name.c_str(), pids.size());
            }
        }
    }
};

int main() {
    LOGI("Process guard starting...");
    
    // 读取配置文件
    std::ifstream configFile("config.json");
    if (UNLIKELY(!configFile.is_open())) {
        LOGE("Failed to open config.json");
        return 1;
    }
    
    json config;
    try {
        configFile >> config;
    } catch (const std::exception& e) {
        LOGE("JSON parse error: %s", e.what());
        return 1;
    }
    
    // 解析扫描间隔（单位：秒）
    int scan_interval = 1; // 默认1秒
    if (config.contains("scan_interval")) {
        try {
            scan_interval = config["scan_interval"].get<int>();
            if (scan_interval < 1) {
                LOGW("Invalid scan_interval %d, using default 1", scan_interval);
                scan_interval = 1;
            }
        } catch (const std::exception& e) {
            LOGE("Failed to parse scan_interval: %s, using default 1", e.what());
        }
    }
    
    // 解析进程列表
    std::vector<json> processes;
    if (config.contains("processes")) {
        processes = config["processes"].get<std::vector<json>>();
    } else {
        // 兼容旧格式：整个数组就是进程列表
        processes = config.get<std::vector<json>>();
    }
    
    // 创建进程守护对象
    std::vector<ProcessGuard> guards;
    for (const auto& item : processes) {
        guards.emplace_back(
            item["name"].get<std::string>(),
            item["cwd"].get<std::string>(),
            item["cmdline"].get<std::string>(),
            item["autorun"].get<bool>()
        );
    }
    
    LOGI("Initialized %zu process guards, scan interval: %d seconds", 
         guards.size(), scan_interval);
    
    // 等待系统稳定
    sleep(5);
    
    LOGI("Starting guard loop...");
    
    // 主守护循环
    while (true) {
        for (auto& guard : guards) {
            guard.guard();
            usleep(5000); 
        }
        // 使用配置的扫描间隔
        sleep(scan_interval);
    }
    
    return 0;
}