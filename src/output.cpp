#include "output.h"

#include <algorithm>
#include <sstream>

#include "util.h"

namespace {

std::string TruncateForTokenMode(const std::string& s, TokenMode mode) {
    if (mode == TokenMode::kNormal) {
        return s;
    }
    constexpr size_t kMaxLen = 220;
    if (s.size() <= kMaxLen) {
        return s;
    }
    return s.substr(0, kMaxLen) + "...";
}

std::vector<std::string> CompactList(const std::vector<std::string>& values, TokenMode mode) {
    if (mode == TokenMode::kNormal) {
        return values;
    }
    std::vector<std::string> out;
    const size_t limit = std::min<size_t>(2, values.size());
    for (size_t i = 0; i < limit; ++i) {
        out.push_back(TruncateForTokenMode(values[i], mode));
    }
    return out;
}

std::string Paint(const std::string& text, const char* ansi, bool no_color) {
    if (no_color) {
        return text;
    }
    return std::string(ansi) + text + "\x1b[0m";
}

const char* SeverityColor(Severity severity) {
    switch (severity) {
        case Severity::kInfo:
            return "\x1b[37m";
        case Severity::kWarning:
            return "\x1b[33m";
        case Severity::kCritical:
        case Severity::kError:
            return "\x1b[31m";
    }
    return "\x1b[37m";
}

std::string SeverityBadge(Severity severity, bool no_color) {
    const std::string label = "[" + SeverityToString(severity) + "]";
    return Paint(label, SeverityColor(severity), no_color);
}

std::string SectionTitle(const std::string& text, bool no_color) {
    return Paint(text, "\x1b[36m", no_color);
}

std::string Label(const std::string& text, bool no_color) {
    return Paint(text, "\x1b[90m", no_color);
}

std::string SoftBullet(const std::string& text, bool no_color) {
    return Paint(text, "\x1b[2m", no_color);
}

void RenderPrettyResult(const Context& context, const CollectorResult& result, std::ostringstream* out) {
    *out << SectionTitle("## " + result.collector_id, context.no_color) << "\n";

    if (!result.metadata.empty()) {
        *out << Label("Metadata:", context.no_color) << "\n";
        for (const auto& kv : result.metadata) {
            *out << SoftBullet("- ", context.no_color) << kv.first << ": "
                 << TruncateForTokenMode(kv.second, context.token_mode) << "\n";
        }
    }

    if (!result.errors.empty()) {
        *out << Paint("Errors:", "\x1b[31m", context.no_color) << "\n";
        for (const auto& error : result.errors) {
            *out << SoftBullet("- ", context.no_color) << error << "\n";
        }
    }

    if (result.findings.empty()) {
        *out << Label("Findings:", context.no_color) << "\n";
        *out << SoftBullet("- ", context.no_color) << Paint("none", "\x1b[90m", context.no_color) << "\n\n";
        return;
    }

    *out << Label("Findings:", context.no_color) << "\n";
    for (const auto& finding : result.findings) {
        *out << SoftBullet("- ", context.no_color)
             << SeverityBadge(finding.severity, context.no_color)
             << " "
             << Paint(finding.id, "\x1b[36m", context.no_color)
             << " - "
             << Paint(finding.title, SeverityColor(finding.severity), context.no_color)
             << "\n";

        *out << "  " << Label("Summary:", context.no_color) << " "
             << TruncateForTokenMode(finding.summary, context.token_mode) << "\n";
        *out << "  " << Label("Confidence:", context.no_color) << " " << finding.confidence << "\n";
        *out << "  " << Label("Source:", context.no_color) << " " << finding.source << "\n";

        const auto evidence = CompactList(finding.evidence, context.token_mode);
        if (!evidence.empty()) {
            *out << "  " << Label("Evidence:", context.no_color) << "\n";
            for (const auto& item : evidence) {
                *out << "  " << SoftBullet("* ", context.no_color)
                     << TruncateForTokenMode(item, context.token_mode) << "\n";
            }
        }

        const auto causes = CompactList(finding.likely_causes, context.token_mode);
        if (!causes.empty()) {
            *out << "  " << Paint("Likely causes:", "\x1b[33m", context.no_color) << "\n";
            for (const auto& item : causes) {
                *out << "  " << SoftBullet("* ", context.no_color)
                     << TruncateForTokenMode(item, context.token_mode) << "\n";
            }
        }

        const auto checks = CompactList(finding.next_checks, context.token_mode);
        if (!checks.empty()) {
            *out << "  " << Paint("Next checks:", "\x1b[32m", context.no_color) << "\n";
            for (const auto& item : checks) {
                *out << "  " << SoftBullet("* ", context.no_color)
                     << TruncateForTokenMode(item, context.token_mode) << "\n";
            }
        }

        if (!finding.metadata.empty()) {
            *out << "  " << Label("Fields:", context.no_color) << "\n";
            for (const auto& kv : finding.metadata) {
                *out << "  " << SoftBullet("* ", context.no_color)
                     << kv.first << "=" << TruncateForTokenMode(kv.second, context.token_mode) << "\n";
            }
        }
    }

    *out << "\n";
}

void RenderTaggedResult(const Context& context, const CollectorResult& result, std::ostringstream* out) {
    *out << "BEGIN_SECTION id=" << result.collector_id << "\n";

    for (const auto& kv : result.metadata) {
        *out << "meta." << kv.first << "=" << TruncateForTokenMode(kv.second, context.token_mode) << "\n";
    }

    for (const auto& error : result.errors) {
        *out << "error=" << TruncateForTokenMode(error, context.token_mode) << "\n";
    }

    size_t idx = 0;
    for (const auto& finding : result.findings) {
        *out << "finding." << idx << ".id=" << finding.id << "\n";
        *out << "finding." << idx << ".severity=" << SeverityToString(finding.severity) << "\n";
        *out << "finding." << idx << ".title=" << TruncateForTokenMode(finding.title, context.token_mode) << "\n";
        *out << "finding." << idx << ".summary=" << TruncateForTokenMode(finding.summary, context.token_mode) << "\n";
        *out << "finding." << idx << ".confidence=" << finding.confidence << "\n";
        *out << "finding." << idx << ".source=" << TruncateForTokenMode(finding.source, context.token_mode) << "\n";

        const auto evidence = CompactList(finding.evidence, context.token_mode);
        for (size_t j = 0; j < evidence.size(); ++j) {
            *out << "finding." << idx << ".evidence." << j << "=" << TruncateForTokenMode(evidence[j], context.token_mode) << "\n";
        }
        const auto causes = CompactList(finding.likely_causes, context.token_mode);
        for (size_t j = 0; j < causes.size(); ++j) {
            *out << "finding." << idx << ".cause." << j << "=" << TruncateForTokenMode(causes[j], context.token_mode) << "\n";
        }
        const auto checks = CompactList(finding.next_checks, context.token_mode);
        for (size_t j = 0; j < checks.size(); ++j) {
            *out << "finding." << idx << ".check." << j << "=" << TruncateForTokenMode(checks[j], context.token_mode) << "\n";
        }
        for (const auto& kv : finding.metadata) {
            *out << "finding." << idx << ".field." << kv.first << "=" << TruncateForTokenMode(kv.second, context.token_mode) << "\n";
        }
        ++idx;
    }

    *out << "END_SECTION id=" << result.collector_id << "\n";
}

}  // namespace

std::string RenderReport(const Context& context, const std::vector<CollectorResult>& results) {
    std::ostringstream out;

    if (context.format == OutputFormat::kPretty) {
        out << Paint("SYSINF REPORT", "\x1b[1;36m", context.no_color) << "\n";
        out << Label("command", context.no_color) << "=" << static_cast<int>(context.command)
            << " " << Label("verbosity", context.no_color) << "=" << context.verbosity
            << " " << Label("since", context.no_color) << "=" << context.since
            << " " << Label("max_events", context.no_color) << "=" << context.max_events
            << " " << Label("token_mode", context.no_color) << "="
            << (context.token_mode == TokenMode::kNormal ? "normal" : "economy")
            << "\n\n";

        for (const auto& result : results) {
            RenderPrettyResult(context, result, &out);
        }
        return out.str();
    }

    out << "BEGIN_REPORT\n";
    out << "context.verbosity=" << context.verbosity << "\n";
    out << "context.since=" << context.since << "\n";
    out << "context.max_events=" << context.max_events << "\n";
    out << "context.token_mode=" << (context.token_mode == TokenMode::kNormal ? "normal" : "economy") << "\n";

    for (const auto& result : results) {
        RenderTaggedResult(context, result, &out);
    }

    out << "END_REPORT\n";
    return out.str();
}

bool HasHighPriorityFindings(const std::vector<CollectorResult>& results) {
    for (const auto& result : results) {
        if (!result.errors.empty()) {
            return true;
        }
        for (const auto& finding : result.findings) {
            if (finding.severity != Severity::kInfo) {
                return true;
            }
        }
    }
    return false;
}
