#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "cli.h"
#include "output.h"

namespace {

void Assert(bool cond, const std::string& message) {
    if (!cond) {
        std::cerr << "Assertion failed: " << message << "\n";
        std::exit(1);
    }
}

ParseResult Parse(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>("sysinf"));
    for (const auto& s : args) {
        argv.push_back(const_cast<char*>(s.c_str()));
    }
    return ParseCli(static_cast<int>(argv.size()), argv.data());
}

void TestCliParsing() {
    {
        ParseResult pr = Parse({"topic", "--target", "thermal,io-latency", "--include", "sensors,queue", "--exclude", "queue", "--sources", "perfcounter.gpu", "--level", "deep"});
        Assert(pr.ok, "topic parse should succeed");
        Assert(pr.context.requested_topics.size() == 2, "topic csv parsed");
        Assert(pr.context.include_facets.contains("sensors"), "include facet parsed");
        Assert(pr.context.exclude_facets.contains("queue"), "exclude facet parsed");
        Assert(pr.context.source_overrides.contains("perfcounter.gpu"), "sources parsed");
        Assert(pr.context.level == CollectionLevel::kDeep, "level parsed");
    }
    {
        ParseResult pr = Parse({"topic", "--target", "services-health"});
        Assert(pr.ok, "new topic target accepted");
    }
    {
        ParseResult pr = Parse({"topic", "--target", "unknown-topic"});
        Assert(!pr.ok, "unknown topic rejected");
    }
    {
        ParseResult pr = Parse({"summary", "--verbosity", "8"});
        Assert(!pr.ok, "verbosity out of range should fail");
    }
}

void TestOutputDeterminism() {
    Context ctx;
    ctx.command = Command::kTopic;
    ctx.format = OutputFormat::kTagged;
    ctx.level = CollectionLevel::kNormal;
    ctx.no_color = true;
    ctx.requested_topics = {"thermal", "io-latency"};
    ctx.include_facets.insert("sensors");
    ctx.skipped_sources = {"perfcounter.io_latency"};

    CollectorResult res;
    res.collector_id = "thermal";

    Finding f;
    f.id = "thermal.sensors";
    f.title = "Thermal sensor snapshot";
    f.summary = "Telemetry captured.";
    f.severity = Severity::kInfo;
    f.confidence = 0.9;
    f.source = "wmi.thermalzone";
    f.evidence = {"line1", "line2", "line3"};
    res.findings.push_back(f);

    std::vector<CollectorResult> results = {res};

    const std::string tagged = RenderReport(ctx, results);
    Assert(tagged.find("BEGIN_REPORT") != std::string::npos, "tagged has begin report");
    Assert(tagged.find("context.requested_topics=thermal,io-latency") != std::string::npos, "tagged includes requested topics");
    Assert(tagged.find("context.skipped_sources=perfcounter.io_latency") != std::string::npos, "tagged includes skipped sources");
    Assert(tagged.find("BEGIN_SECTION id=thermal") != std::string::npos, "tagged has section");

    ctx.format = OutputFormat::kPretty;
    ctx.token_mode = TokenMode::kEconomy;
    const std::string pretty = RenderReport(ctx, results);
    Assert(pretty.find("requested_topics") != std::string::npos, "pretty includes topics key in header");
    Assert(pretty.find("thermal,io-latency") != std::string::npos, "pretty includes topics value in header");

    const size_t evidence_count =
        (pretty.find("* line1") != std::string::npos) +
        (pretty.find("* line2") != std::string::npos) +
        (pretty.find("* line3") != std::string::npos);
    Assert(evidence_count <= 2, "economy mode should compact evidence lines");
}

}  // namespace

int main() {
    TestCliParsing();
    TestOutputDeterminism();
    std::cout << "sysinf_tests passed\n";
    return 0;
}
