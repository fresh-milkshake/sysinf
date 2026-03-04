#include "collectors/common.h"

#include <algorithm>
#include <chrono>
#include <sstream>

#include "util.h"

namespace collectors_internal {

namespace {

std::vector<std::string> Lines(const std::string& raw, size_t max_lines) {
    std::vector<std::string> out;
    for (const auto& l : SplitLines(raw)) {
        if (!l.empty()) {
            out.push_back(l);
        }
        if (out.size() >= max_lines) {
            break;
        }
    }
    return out;
}

void PushUnique(std::vector<std::string>* v, const std::string& item) {
    if (std::find(v->begin(), v->end(), item) == v->end()) {
        v->push_back(item);
    }
}

bool FacetOn(const Context& c, const std::string& facet) {
    const std::string f = ToLower(facet);
    if (c.exclude_facets.contains(f)) {
        return false;
    }
    return c.include_facets.empty() || c.include_facets.contains(f);
}

bool HeavyAllowed(Context& c, const std::string& source) {
    if (c.level == CollectionLevel::kDeep || c.source_overrides.contains(ToLower(source))) {
        return true;
    }
    PushUnique(&c.skipped_sources, source);
    return false;
}

bool Run(Context& c,
         CollectorResult* r,
         const std::string& source,
         const std::string& cmd,
         bool heavy,
         bool admin,
         size_t max_lines,
         std::vector<std::string>* out) {
    out->clear();

    if (admin && !c.is_admin) {
        PushUnique(&c.denied_sources, source);
        auto f = Mk("source_permission_denied." + source,
                    "Source requires admin privileges",
                    "Collector continued with partial data because this source requires elevation.",
                    Severity::kWarning,
                    0.98,
                    source);
        f.metadata["category"] = "source_permission_denied";
        r->findings.push_back(f);
        return false;
    }

    if (heavy && !HeavyAllowed(c, source)) {
        auto f = Mk("source_skipped_budget." + source,
                    "Heavy source skipped by budget policy",
                    "Source skipped in quick/normal level to keep runtime budget within ~20s.",
                    Severity::kInfo,
                    0.98,
                    source);
        f.metadata["category"] = "source_skipped_budget";
        r->findings.push_back(f);
        return false;
    }

    int code = 0;
    const auto t0 = std::chrono::steady_clock::now();
    const std::string raw = RunCommand(cmd, &code);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    if (elapsed > c.per_source_timeout_ms) {
        PushUnique(&c.timed_out_sources, source);
        auto f = Mk("source_timeout." + source,
                    "Source exceeded timeout budget",
                    "Source completed slower than timeout budget and may reduce responsiveness.",
                    Severity::kWarning,
                    0.9,
                    source);
        f.metadata["category"] = "source_timeout";
        f.metadata["timeout_ms"] = std::to_string(c.per_source_timeout_ms);
        f.metadata["elapsed_ms"] = std::to_string(elapsed);
        r->findings.push_back(f);
    }

    if (code != 0) {
        auto f = Mk("source_failed." + source,
                    "Data source execution failure",
                    "A source command failed and reduced confidence.",
                    Severity::kWarning,
                    0.95,
                    source);
        f.evidence.push_back("command=" + cmd);
        f.evidence.push_back("exit_code=" + std::to_string(code));
        r->findings.push_back(f);
        return false;
    }

    *out = Lines(raw, max_lines);
    return true;
}

}  // namespace

Finding Mk(const std::string& id,
           const std::string& title,
           const std::string& sum,
           Severity sev,
           double conf,
           const std::string& src) {
    Finding f;
    f.id = id;
    f.title = title;
    f.summary = sum;
    f.severity = sev;
    f.confidence = conf;
    f.source = src;
    return f;
}

std::string Ps(const std::string& body) {
    return "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + body + "\"";
}

std::string Evt(const std::string& log_name, const std::string& ids_csv, const std::string& since_expr, int max_events) {
    std::ostringstream q;
    q << "$s=" << since_expr << "; Get-WinEvent -FilterHashtable @{LogName='" << log_name << "'; Id=" << ids_csv
      << "; StartTime=$s} -MaxEvents " << max_events
      << " | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List";
    return Ps(q.str());
}

void Meta(const Context& c, CollectorResult* r) {
    r->metadata["level"] = CollectionLevelToString(c.level);
    r->metadata["timeout_ms"] = std::to_string(c.per_source_timeout_ms);
}

void AddPartial(Context& c, CollectorResult* r) {
    if (c.skipped_sources.empty() && c.denied_sources.empty() && c.timed_out_sources.empty()) {
        return;
    }
    auto f = Mk("partial_collection." + r->collector_id,
                "Collection completed with partial coverage",
                "Some sources were skipped, denied, or exceeded timeout budget.",
                Severity::kWarning,
                0.8,
                r->collector_id);
    f.metadata["category"] = "partial_collection";
    f.metadata["skipped_sources"] = std::to_string(c.skipped_sources.size());
    f.metadata["denied_sources"] = std::to_string(c.denied_sources.size());
    f.metadata["timed_out_sources"] = std::to_string(c.timed_out_sources.size());
    r->findings.push_back(f);
}

void AddProbe(Context& c,
              CollectorResult* r,
              const std::string& id,
              const std::string& title,
              const std::string& summary,
              const std::string& source,
              const std::string& cmd,
              bool heavy,
              bool admin,
              size_t max_lines,
              const std::string& facet) {
    if (!facet.empty() && !FacetOn(c, facet)) {
        return;
    }
    std::vector<std::string> out;
    if (!Run(c, r, source, cmd, heavy, admin, max_lines, &out)) {
        return;
    }
    auto f = Mk(id, title, summary, Severity::kInfo, 0.8, source);
    f.evidence = out;
    r->findings.push_back(f);
}

}  // namespace collectors_internal
