#ifndef SYSINF_RUNTIME_STATUS_H
#define SYSINF_RUNTIME_STATUS_H

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

class RuntimeStatus {
public:
    RuntimeStatus(bool enabled, bool no_color);
    ~RuntimeStatus();

    void Start(std::size_t total_sections);
    void SetCurrent(std::size_t current_section_index, const std::string& section_name);
    void CompleteCurrent();
    void Stop();

private:
    void RenderLoop();
    std::string FormatLine(char frame) const;
    std::string FormatElapsed(std::chrono::steady_clock::time_point now) const;

    bool enabled_;
    bool no_color_;
    std::atomic<bool> running_;
    std::atomic<std::size_t> done_sections_;
    std::size_t total_sections_;
    std::string current_section_;
    std::chrono::steady_clock::time_point started_at_;
    mutable std::mutex mutex_;
    std::thread worker_;
};

#endif
