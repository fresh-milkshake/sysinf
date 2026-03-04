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
        ParseResult pr = Parse({"summary", "--verbosity", "3", "--format", "tagged", "--token-mode", "economy", "--since", "12h", "--max-events", "50"});
        Assert(pr.ok, "summary parse should succeed");
        Assert(pr.context.verbosity == 3, "verbosity parsed");
        Assert(pr.context.format == OutputFormat::kTagged, "format parsed");
        Assert(pr.context.token_mode == TokenMode::kEconomy, "token mode parsed");
        Assert(pr.context.since == "12h", "since parsed");
        Assert(pr.context.max_events == 50, "max events parsed");
    }
    {
        ParseResult pr = Parse({"incident", "--preset", "shutdown"});
        Assert(pr.ok, "incident shutdown parse should succeed");
        Assert(pr.context.sub_target == "shutdown", "preset parsed");
    }
    {
        ParseResult pr = Parse({"topic", "--target", "storage"});
        Assert(pr.ok, "topic storage parse should succeed");
        Assert(pr.context.sub_target == "storage", "target parsed");
    }
    {
        ParseResult pr = Parse({"summary", "--verbosity", "8"});
        Assert(!pr.ok, "verbosity out of range should fail");
    }
    {
        ParseResult pr = Parse({"incident"});
        Assert(!pr.ok, "incident without preset should fail");
    }
}

void TestOutputDeterminism() {
    Context ctx;
    ctx.command = Command::kSummary;
    ctx.format = OutputFormat::kTagged;

    CollectorResult res;
    res.collector_id = "system_baseline";

    Finding f;
    f.id = "sys.os.baseline";
    f.title = "OS baseline captured";
    f.summary = "Windows baseline info captured successfully.";
    f.severity = Severity::kInfo;
    f.confidence = 0.9;
    f.source = "cim/win32_operatingsystem";
    f.evidence = {"line1", "line2", "line3"};
    f.likely_causes = {"cause1", "cause2", "cause3"};
    f.next_checks = {"check1", "check2", "check3"};
    res.findings.push_back(f);

    std::vector<CollectorResult> results = {res};

    const std::string tagged = RenderReport(ctx, results);
    Assert(tagged.find("BEGIN_REPORT") != std::string::npos, "tagged has begin report");
    Assert(tagged.find("BEGIN_SECTION id=system_baseline") != std::string::npos, "tagged has section");
    Assert(tagged.find("finding.0.id=sys.os.baseline") != std::string::npos, "tagged includes finding id");

    ctx.format = OutputFormat::kPretty;
    ctx.token_mode = TokenMode::kEconomy;
    const std::string pretty = RenderReport(ctx, results);
    Assert(pretty.find("Likely causes") != std::string::npos, "pretty includes likely causes block");

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
