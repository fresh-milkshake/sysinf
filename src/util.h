#ifndef SYSINF_UTIL_H
#define SYSINF_UTIL_H

#include <string>
#include <vector>

bool IsRunningAsAdmin();

std::string RunCommand(const std::string& command, int* exit_code = nullptr);
std::vector<std::string> SplitLines(const std::string& text);
std::string Trim(const std::string& s);
std::string ToLower(std::string s);
bool StartsWith(const std::string& s, const std::string& prefix);

std::string BuildPowerShellSinceExpression(const std::string& since);

#endif
