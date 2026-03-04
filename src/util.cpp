#include "util.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <regex>
#include <sstream>

bool IsRunningAsAdmin() {
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;
    if (!AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &admin_group)) {
        return false;
    }

    BOOL is_admin = FALSE;
    if (!CheckTokenMembership(nullptr, admin_group, &is_admin)) {
        is_admin = FALSE;
    }

    FreeSid(admin_group);
    return is_admin == TRUE;
}

std::string RunCommand(const std::string& command, int* exit_code) {
    std::string output;
    std::array<char, 512> buffer{};

    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        if (exit_code != nullptr) {
            *exit_code = -1;
        }
        return "";
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }

    int code = _pclose(pipe);
    if (exit_code != nullptr) {
        *exit_code = code;
    }
    return output;
}

std::string Trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])) != 0) {
        ++start;
    }

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        --end;
    }

    return s.substr(start, end - start);
}

std::vector<std::string> SplitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        lines.push_back(Trim(line));
    }
    return lines;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool StartsWith(const std::string& s, const std::string& prefix) {
    if (prefix.size() > s.size()) {
        return false;
    }
    return std::equal(prefix.begin(), prefix.end(), s.begin());
}

std::string BuildPowerShellSinceExpression(const std::string& since) {
    const std::string trimmed = Trim(since);
    const std::string lower = ToLower(trimmed);

    std::smatch match;
    const std::regex duration_re("^([0-9]+)([mhdw])$");
    if (std::regex_match(lower, match, duration_re)) {
        const int value = std::stoi(match[1].str());
        const std::string unit = match[2].str();
        if (unit == "m") {
            return "(Get-Date).AddMinutes(-" + std::to_string(value) + ")";
        }
        if (unit == "h") {
            return "(Get-Date).AddHours(-" + std::to_string(value) + ")";
        }
        if (unit == "d") {
            return "(Get-Date).AddDays(-" + std::to_string(value) + ")";
        }
        if (unit == "w") {
            return "(Get-Date).AddDays(-" + std::to_string(value * 7) + ")";
        }
    }

    return "[datetime]'" + trimmed + "'";
}
