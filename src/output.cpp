#include "output.h"

#include <algorithm>
#include <sstream>

#include "util.h"

namespace {

struct SeverityStats {
    int info = 0;
    int warning = 0;
    int critical = 0;
    int error = 0;
    int total = 0;
};

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

std::string JoinSet(const std::set<std::string>& values) {
    std::ostringstream out;
    bool first = true;
    for (const auto& v : values) {
        if (!first) out << ",";
        out << v;
        first = false;
    }
    return out.str();
}

std::string JoinVector(const std::vector<std::string>& values) {
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) out << ",";
        out << values[i];
    }
    return out.str();
}

SeverityStats BuildSeverityStats(const std::vector<CollectorResult>& results) {
    SeverityStats stats;
    for (const auto& result : results) {
        for (const auto& finding : result.findings) {
            ++stats.total;
            switch (finding.severity) {
                case Severity::kInfo:
                    ++stats.info;
                    break;
                case Severity::kWarning:
                    ++stats.warning;
                    break;
                case Severity::kCritical:
                    ++stats.critical;
                    break;
                case Severity::kError:
                    ++stats.error;
                    break;
            }
        }
    }
    return stats;
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
    const SeverityStats stats = BuildSeverityStats(results);

    if (context.format == OutputFormat::kPretty) {
        out << Paint("SYSINF REPORT", "\x1b[1;36m", context.no_color) << "\n";
        out << Label("command", context.no_color) << "=" << static_cast<int>(context.command)
            << " " << Label("verbosity", context.no_color) << "=" << context.verbosity
            << " " << Label("since", context.no_color) << "=" << context.since
            << " " << Label("max_events", context.no_color) << "=" << context.max_events
            << " " << Label("level", context.no_color) << "=" << CollectionLevelToString(context.level)
            << " " << Label("token_mode", context.no_color) << "="
            << (context.token_mode == TokenMode::kNormal ? "normal" : "economy")
            << "\n";
        out << Label("sections", context.no_color) << "=" << results.size()
            << " " << Label("findings_total", context.no_color) << "=" << stats.total
            << " " << Label("info", context.no_color) << "=" << stats.info
            << " " << Label("warning", context.no_color) << "=" << stats.warning
            << " " << Label("critical", context.no_color) << "=" << stats.critical
            << " " << Label("error", context.no_color) << "=" << stats.error << "\n";
        out << Label("requested_topics", context.no_color) << "=" << JoinVector(context.requested_topics) << "\n";
        out << Label("include", context.no_color) << "=" << JoinSet(context.include_facets) << "\n";
        out << Label("exclude", context.no_color) << "=" << JoinSet(context.exclude_facets) << "\n";
        out << Label("sources", context.no_color) << "=" << JoinSet(context.source_overrides) << "\n";
        out << Label("is_admin", context.no_color) << "=" << (context.is_admin ? "true" : "false") << "\n";
        out << Label("skipped_sources", context.no_color) << "=" << JoinVector(context.skipped_sources) << "\n";
        out << Label("denied_sources", context.no_color) << "=" << JoinVector(context.denied_sources) << "\n";
        out << Label("timed_out_sources", context.no_color) << "=" << JoinVector(context.timed_out_sources) << "\n\n";

        out << SectionTitle("## Summary", context.no_color) << "\n";
        if (stats.total == 0) {
            out << SoftBullet("- ", context.no_color) << Paint("No findings were produced by active collectors.", "\x1b[90m", context.no_color) << "\n";
        } else {
            out << SoftBullet("- ", context.no_color) << "Collector sections processed: " << results.size() << "\n";
            out << SoftBullet("- ", context.no_color) << "Findings by severity: "
                << "info=" << stats.info << ", warning=" << stats.warning << ", critical=" << stats.critical << ", error=" << stats.error << "\n";
        }
        if (!context.skipped_sources.empty() || !context.denied_sources.empty() || !context.timed_out_sources.empty()) {
            out << SoftBullet("- ", context.no_color) << "Collection state: "
                << "skipped=" << context.skipped_sources.size()
                << ", denied=" << context.denied_sources.size()
                << ", timed_out=" << context.timed_out_sources.size() << "\n";
        }
        out << "\n";

        for (const auto& result : results) {
            RenderPrettyResult(context, result, &out);
        }
        return out.str();
    }

    out << "BEGIN_REPORT\n";
    out << "context.verbosity=" << context.verbosity << "\n";
    out << "context.since=" << context.since << "\n";
    out << "context.max_events=" << context.max_events << "\n";
    out << "context.level=" << CollectionLevelToString(context.level) << "\n";
    out << "context.sections=" << results.size() << "\n";
    out << "summary.total_findings=" << stats.total << "\n";
    out << "summary.info=" << stats.info << "\n";
    out << "summary.warning=" << stats.warning << "\n";
    out << "summary.critical=" << stats.critical << "\n";
    out << "summary.error=" << stats.error << "\n";
    out << "context.requested_topics=" << JoinVector(context.requested_topics) << "\n";
    out << "context.include=" << JoinSet(context.include_facets) << "\n";
    out << "context.exclude=" << JoinSet(context.exclude_facets) << "\n";
    out << "context.sources=" << JoinSet(context.source_overrides) << "\n";
    out << "context.is_admin=" << (context.is_admin ? "true" : "false") << "\n";
    out << "context.skipped_sources=" << JoinVector(context.skipped_sources) << "\n";
    out << "context.denied_sources=" << JoinVector(context.denied_sources) << "\n";
    out << "context.timed_out_sources=" << JoinVector(context.timed_out_sources) << "\n";

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
