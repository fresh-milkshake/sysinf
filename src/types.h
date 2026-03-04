#ifndef SYSINF_TYPES_H
#define SYSINF_TYPES_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

enum class Severity {
    kInfo = 0,
    kWarning = 1,
    kCritical = 2,
    kError = 3,
};

inline std::string SeverityToString(Severity severity) {
    switch (severity) {
        case Severity::kInfo:
            return "info";
        case Severity::kWarning:
            return "warning";
        case Severity::kCritical:
            return "critical";
        case Severity::kError:
            return "error";
    }
    return "unknown";
}

struct Finding {
    std::string id;
    std::string title;
    std::string summary;
    Severity severity = Severity::kInfo;
    double confidence = 0.5;
    std::string source;
    std::vector<std::string> evidence;
    std::vector<std::string> likely_causes;
    std::vector<std::string> next_checks;
    std::map<std::string, std::string> metadata;
};

struct CollectorResult {
    std::string collector_id;
    std::vector<Finding> findings;
    std::vector<std::string> errors;
    std::map<std::string, std::string> metadata;
};

enum class OutputFormat {
    kPretty,
    kTagged,
};

enum class TokenMode {
    kNormal,
    kEconomy,
};

enum class Command {
    kHelp,
    kSummary,
    kIncident,
    kHardware,
    kLogs,
    kCrash,
    kTopic,
};

struct Context {
    Command command = Command::kHelp;
    std::string sub_target;
    int verbosity = 1;
    OutputFormat format = OutputFormat::kPretty;
    TokenMode token_mode = TokenMode::kNormal;
    std::string since = "24h";
    std::int32_t max_events = 100;
    bool no_color = false;
};

#endif
