#include <iostream>
#include <vector>

#include "cli.h"
#include "collectors.h"
#include "output.h"
#include "runtime_status.h"
#include "util.h"

int main(int argc, char** argv) {
    ParseResult parse = ParseCli(argc, argv);
    if (!parse.ok) {
        std::cerr << "Error: " << parse.error << "\n\n";
        std::cerr << BuildHelpText() << "\n";
        return 1;
    }

    if (parse.show_help) {
        std::string sub;
        if (argc >= 2) {
            const std::string candidate = argv[1];
            if (candidate != "-h" && candidate != "--help" && candidate != "help") {
                sub = candidate;
            }
        }
        std::cout << BuildHelpText(sub) << "\n";
        return 0;
    }

    Context context = parse.context;
    context.is_admin = IsRunningAsAdmin();
    if (context.command == Command::kSummary && context.requested_topics.empty()) {
        context.requested_topics = {"system", "hardware", "storage", "power", "services-health"};
    }

    const auto collectors = BuildCollectorsForContext(context);
    std::vector<CollectorResult> results;
    results.reserve(collectors.size());

    RuntimeStatus status(/*enabled=*/true, context.no_color);
    status.Start(collectors.size());

    for (std::size_t i = 0; i < collectors.size(); ++i) {
        const auto& collector = collectors[i];
        status.SetCurrent(i, collector->DisplayName());
        results.push_back(collector->Collect(context));
        status.CompleteCurrent();
    }

    status.Stop();

    std::cout << RenderReport(context, results);
    return HasHighPriorityFindings(results) ? 1 : 0;
}
