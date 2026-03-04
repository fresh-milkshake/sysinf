#include "runtime_status.h"

#include <io.h>

#include <iomanip>
#include <iostream>
#include <sstream>

namespace {

bool IsInteractiveStderr() {
    return _isatty(_fileno(stderr)) != 0;
}

std::string Color(const std::string& code, const std::string& value, bool no_color) {
    if (no_color) {
        return value;
    }
    return code + value + "\x1b[0m";
}

}  // namespace

RuntimeStatus::RuntimeStatus(bool enabled, bool no_color)
    : enabled_(enabled && IsInteractiveStderr()),
      no_color_(no_color),
      running_(false),
      done_sections_(0),
      total_sections_(0),
      current_section_("initializing"),
      started_at_(std::chrono::steady_clock::now()) {}

RuntimeStatus::~RuntimeStatus() {
    Stop();
}

void RuntimeStatus::Start(std::size_t total_sections) {
    if (!enabled_) {
        return;
    }

    total_sections_ = total_sections;
    done_sections_.store(0);
    started_at_ = std::chrono::steady_clock::now();
    running_.store(true);
    worker_ = std::thread(&RuntimeStatus::RenderLoop, this);
}

void RuntimeStatus::SetCurrent(std::size_t current_section_index, const std::string& section_name) {
    if (!enabled_) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        current_section_ = section_name;
    }
    done_sections_.store(current_section_index);
}

void RuntimeStatus::CompleteCurrent() {
    if (!enabled_) {
        return;
    }

    const std::size_t done = done_sections_.load() + 1;
    done_sections_.store(done);

    std::string section;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        section = current_section_;
    }

    std::ostringstream out;
    out << "\r\x1b[2K";
    out << Color("\x1b[32m", "[done]", no_color_) << " "
        << section << " (" << done << "/" << total_sections_ << ")";
    std::cerr << out.str() << std::endl;
}

void RuntimeStatus::Stop() {
    if (!enabled_) {
        return;
    }

    const bool was_running = running_.exchange(false);
    if (was_running && worker_.joinable()) {
        worker_.join();
    }

    std::cerr << "\r\x1b[2K";
    std::cerr.flush();
}

void RuntimeStatus::RenderLoop() {
    static constexpr char kFrames[] = {'|', '/', '-', '\\'};
    std::size_t frame_index = 0;

    while (running_.load()) {
        const char frame = kFrames[frame_index % 4];
        frame_index++;

        std::cerr << "\r\x1b[2K" << FormatLine(frame);
        std::cerr.flush();

        std::this_thread::sleep_for(std::chrono::milliseconds(90));
    }
}

std::string RuntimeStatus::FormatLine(char frame) const {
    std::string section;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        section = current_section_;
    }

    const std::size_t done = done_sections_.load();
    std::ostringstream out;
    out << Color("\x1b[36m", "[collect]", no_color_) << " "
        << frame << " "
        << section
        << "  (" << done << "/" << total_sections_ << ")"
        << "  elapsed=" << FormatElapsed(std::chrono::steady_clock::now());
    return out.str();
}

std::string RuntimeStatus::FormatElapsed(std::chrono::steady_clock::time_point now) const {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now - started_at_).count();
    const int mm = static_cast<int>(seconds / 60);
    const int ss = static_cast<int>(seconds % 60);

    std::ostringstream out;
    out << std::setfill('0') << std::setw(2) << mm << ":" << std::setw(2) << ss;
    return out.str();
}
