#include "cli.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <io.h>
#include <sstream>

#include "util.h"

namespace {

bool HelpUseColor() {
    const char* no_color = std::getenv("NO_COLOR");
    if (no_color != nullptr) {
        return false;
    }
    return _isatty(_fileno(stdout)) != 0;
}

std::string PaintHelp(const std::string& text, const char* ansi) {
    if (!HelpUseColor()) {
        return text;
    }
    return std::string(ansi) + text + "\x1b[0m";
}

std::string H1(const std::string& text) {
    return PaintHelp(text, "\x1b[1;36m");
}

std::string H2(const std::string& text) {
    return PaintHelp(text, "\x1b[36m");
}

std::string Dim(const std::string& text) {
    return PaintHelp(text, "\x1b[90m");
}

std::string Flag(const std::string& text) {
    return PaintHelp(text, "\x1b[33m");
}

std::vector<std::string> SplitCsvLower(const std::string& value) {
    std::vector<std::string> items;
    std::stringstream ss(value);
    std::string token;
    while (std::getline(ss, token, ',')) {
        const std::string item = ToLower(Trim(token));
        if (!item.empty()) {
            items.push_back(item);
        }
    }
    return items;
}

bool IsKnownCommand(const std::string& command) {
    static const std::vector<std::string> commands = {
        "summary", "incident", "hardware", "logs", "crash", "topic", "help",
    };
    return std::find(commands.begin(), commands.end(), command) != commands.end();
}

Command ParseCommand(const std::string& command) {
    if (command == "summary") {
        return Command::kSummary;
    }
    if (command == "incident") {
        return Command::kIncident;
    }
    if (command == "hardware") {
        return Command::kHardware;
    }
    if (command == "logs") {
        return Command::kLogs;
    }
    if (command == "crash") {
        return Command::kCrash;
    }
    if (command == "topic") {
        return Command::kTopic;
    }
    return Command::kHelp;
}

bool ParseGlobalFlag(const std::vector<std::string>& args, size_t* i, Context* ctx, std::string* error) {
    const std::string& arg = args[*i];

    if (arg == "--verbosity") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --verbosity.";
            return false;
        }
        int level = -1;
        try {
            level = std::stoi(args[*i + 1]);
        } catch (...) {
            *error = "Invalid integer for --verbosity.";
            return false;
        }
        if (level < 0 || level > 5) {
            *error = "--verbosity must be between 0 and 5.";
            return false;
        }
        ctx->verbosity = level;
        *i += 2;
        return true;
    }

    if (arg == "--format") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --format.";
            return false;
        }
        const std::string value = ToLower(args[*i + 1]);
        if (value == "pretty") {
            ctx->format = OutputFormat::kPretty;
        } else if (value == "tagged") {
            ctx->format = OutputFormat::kTagged;
        } else {
            *error = "--format must be pretty|tagged.";
            return false;
        }
        *i += 2;
        return true;
    }

    if (arg == "--token-mode") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --token-mode.";
            return false;
        }
        const std::string value = ToLower(args[*i + 1]);
        if (value == "normal") {
            ctx->token_mode = TokenMode::kNormal;
        } else if (value == "economy") {
            ctx->token_mode = TokenMode::kEconomy;
        } else {
            *error = "--token-mode must be normal|economy.";
            return false;
        }
        *i += 2;
        return true;
    }

    if (arg == "--level") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --level.";
            return false;
        }
        const std::string value = ToLower(args[*i + 1]);
        if (value == "quick") {
            ctx->level = CollectionLevel::kQuick;
        } else if (value == "normal") {
            ctx->level = CollectionLevel::kNormal;
        } else if (value == "deep") {
            ctx->level = CollectionLevel::kDeep;
        } else {
            *error = "--level must be quick|normal|deep.";
            return false;
        }
        *i += 2;
        return true;
    }

    if (arg == "--since") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --since.";
            return false;
        }
        ctx->since = args[*i + 1];
        *i += 2;
        return true;
    }

    if (arg == "--max-events") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --max-events.";
            return false;
        }
        int value = -1;
        try {
            value = std::stoi(args[*i + 1]);
        } catch (...) {
            *error = "Invalid integer for --max-events.";
            return false;
        }
        if (value <= 0) {
            *error = "--max-events must be > 0.";
            return false;
        }
        ctx->max_events = value;
        *i += 2;
        return true;
    }

    if (arg == "--include") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --include.";
            return false;
        }
        for (const auto& item : SplitCsvLower(args[*i + 1])) {
            ctx->include_facets.insert(item);
        }
        *i += 2;
        return true;
    }

    if (arg == "--exclude") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --exclude.";
            return false;
        }
        for (const auto& item : SplitCsvLower(args[*i + 1])) {
            ctx->exclude_facets.insert(item);
        }
        *i += 2;
        return true;
    }

    if (arg == "--sources") {
        if (*i + 1 >= args.size()) {
            *error = "Missing value for --sources.";
            return false;
        }
        for (const auto& item : SplitCsvLower(args[*i + 1])) {
            ctx->source_overrides.insert(item);
        }
        *i += 2;
        return true;
    }

    if (arg == "--no-color") {
        ctx->no_color = true;
        *i += 1;
        return true;
    }

    return false;
}

bool ValidateSubcommandContext(const Context& ctx, std::string* error) {
    if (ctx.command == Command::kIncident) {
        static const std::vector<std::string> presets = {"sound", "shutdown", "crash", "device"};
        if (ctx.sub_target.empty()) {
            *error = "incident requires --preset <sound|shutdown|crash|device>.";
            return false;
        }
        if (std::find(presets.begin(), presets.end(), ToLower(ctx.sub_target)) == presets.end()) {
            *error = "Unknown incident preset: " + ctx.sub_target;
            return false;
        }
    }

    if (ctx.command == Command::kTopic) {
        static const std::vector<std::string> topics = {
            "cpu", "memory", "storage", "gpu", "audio", "power", "network", "drivers", "eventlog", "crash",
            "thermal", "processes", "scheduler", "memory-pressure", "io-latency", "disk-queue", "gpu-telemetry",
            "power-policy", "interrupts", "startup-impact", "services-health", "realtime-audio",
        };
        if (ctx.requested_topics.empty() && ctx.sub_target.empty()) {
            *error = "topic requires --target with at least one topic.";
            return false;
        }
        for (const auto& topic : ctx.requested_topics) {
            if (std::find(topics.begin(), topics.end(), topic) == topics.end()) {
                *error = "Unknown topic target: " + topic;
                return false;
            }
        }
        if (!ctx.sub_target.empty() && std::find(topics.begin(), topics.end(), ctx.sub_target) == topics.end()) {
            *error = "Unknown topic target: " + ctx.sub_target;
            return false;
        }
    }

    return true;
}

}  // namespace

ParseResult ParseCli(int argc, char** argv) {
    ParseResult result;

    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    if (args.empty()) {
        result.ok = true;
        result.show_help = true;
        return result;
    }

    if (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
        result.ok = true;
        result.show_help = true;
        return result;
    }

    if (!IsKnownCommand(ToLower(args[0]))) {
        result.error = "Unknown subcommand: " + args[0];
        return result;
    }

    result.context.command = ParseCommand(ToLower(args[0]));

    size_t i = 1;
    while (i < args.size()) {
        const std::string arg = args[i];

        if (arg == "-h" || arg == "--help") {
            result.ok = true;
            result.show_help = true;
            return result;
        }

        if (ParseGlobalFlag(args, &i, &result.context, &result.error)) {
            continue;
        }

        if (arg == "--preset") {
            if (i + 1 >= args.size()) {
                result.error = "Missing value for --preset";
                return result;
            }
            result.context.sub_target = ToLower(args[i + 1]);
            i += 2;
            continue;
        }

        if (arg == "--target" || arg == "--device-class") {
            if (i + 1 >= args.size()) {
                result.error = "Missing value for " + arg;
                return result;
            }
            result.context.requested_topics = SplitCsvLower(args[i + 1]);
            if (!result.context.requested_topics.empty()) {
                result.context.sub_target = result.context.requested_topics.front();
            }
            i += 2;
            continue;
        }

        result.error = "Unknown argument: " + arg;
        return result;
    }

    if (!ValidateSubcommandContext(result.context, &result.error)) {
        return result;
    }

    result.ok = true;
    return result;
}

std::string BuildHelpText(const std::string& subcommand) {
    const std::string sub = ToLower(subcommand);
    std::ostringstream out;

    if (sub.empty()) {
        out << H1("sysinf.exe - Windows Incident Diagnostics CLI (targeted mode)") << "\n";
        out << Dim("Focused diagnostics for explicit topics and filters.") << "\n\n";
        out << H2("USAGE") << "\n";
        out << "  sysinf <subcommand> [options]\n\n";
        out << H2("SUBCOMMANDS") << "\n";
        out << "  summary   Essential baseline overview (system, hardware, storage, power, services-health)\n";
        out << "  incident  Preset-focused diagnostics\n";
        out << "  hardware  Device and driver-oriented diagnostics\n";
        out << "  logs      Event log diagnostics (System/Application)\n";
        out << "  crash     Crash/BSOD metadata diagnostics\n";
        out << "  topic     Primary command for targeted topic collection\n\n";
        out << H2("GLOBAL OPTIONS") << "\n";
        out << "  " << Flag("--verbosity <0..5>") << "         Default: 1\n";
        out << "  " << Flag("--format <pretty|tagged>") << "   Default: pretty\n";
        out << "  " << Flag("--token-mode <normal|economy>") << "  Default: normal\n";
        out << "  " << Flag("--level <quick|normal|deep>") << "    Default: normal\n";
        out << "  " << Flag("--include <csv>") << "            Include facets inside selected topics\n";
        out << "  " << Flag("--exclude <csv>") << "            Exclude facets inside selected topics\n";
        out << "  " << Flag("--sources <csv>") << "            Force data sources (can enable heavy probes)\n";
        out << "  " << Flag("--since <duration|datetime>") << " Default: 24h (examples: 6h, 2d, 2026-03-01T00:00:00)\n";
        out << "  " << Flag("--max-events <N>") << "           Default: 100\n";
        out << "  " << Flag("--no-color") << "                 Disable ANSI coloring in pretty mode\n\n";
        out << H2("INCIDENT PRESETS") << "\n";
        out << "  sound, shutdown, crash, device\n\n";
        out << H2("TOPIC TARGETS") << "\n";
        out << "  cpu, memory, storage, gpu, audio, power, network, drivers, eventlog, crash\n";
        out << "  thermal, processes, scheduler, memory-pressure, io-latency, disk-queue, gpu-telemetry\n";
        out << "  power-policy, interrupts, startup-impact, services-health, realtime-audio\n\n";
        out << H2("EXAMPLES") << "\n";
        out << "  sysinf summary --level quick\n";
        out << "  sysinf topic --target thermal,io-latency --include sensors,queue --since 2h\n";
        out << "  sysinf topic --target gpu-telemetry --level deep --sources perfcounter,wmi\n";
        out << "  sysinf topic --target startup-impact --exclude scheduledtasks --format tagged\n\n";
        out << H2("EXIT CODES") << "\n";
        out << "  0  Successful run with no warning/critical/error findings\n";
        out << "  1  Any warning/critical/error finding OR runtime collection problem\n";
        return out.str();
    }

    if (sub == "incident") {
        out << H2("USAGE") << "\n";
        out << "  sysinf incident --preset <sound|shutdown|crash|device> [global options]\n\n";
        out << H2("DESCRIPTION") << "\n";
        out << "  Runs incident-specific diagnostics and prints likely causes + next checks.\n";
        return out.str();
    }

    if (sub == "topic") {
        out << H2("USAGE") << "\n";
        out << "  sysinf topic --target <topic[,topic2,...]> [topic options] [global options]\n\n";

        out << H2("DESCRIPTION") << "\n";
        out << "  Primary targeted diagnostics entrypoint.\n";
        out << "  Collects only the requested topic set (no broad fan-out by default).\n\n";

        out << H2("TOPIC OPTIONS") << "\n";
        out << "  " << Flag("--target <csv>") << "       Required. One or more topic names.\n";
        out << "  " << Flag("--include <csv>") << "      Optional facet allow-list inside selected topics.\n";
        out << "  " << Flag("--exclude <csv>") << "      Optional facet block-list (applied after include).\n";
        out << "  " << Flag("--sources <csv>") << "      Force source probes by key (can enable heavy sources).\n";
        out << "  " << Flag("--level quick|normal|deep") << "  Collection depth. Default: normal.\n\n";

        out << H2("LEVELS") << "\n";
        out << "  quick   Fastest path, aggressive skipping of heavy probes.\n";
        out << "  normal  Balanced mode (default), heavy probes skipped unless forced.\n";
        out << "  deep    Enables heavy probes by default for selected topics.\n\n";

        out << H2("TARGET CATALOG") << "\n";
        out << "  Core:\n";
        out << "    cpu, memory, storage, gpu, audio, power, network, drivers, eventlog, crash\n";
        out << "  Perf/Thermal:\n";
        out << "    thermal, processes, scheduler, memory-pressure, io-latency, disk-queue\n";
        out << "    gpu-telemetry, power-policy, interrupts, startup-impact, services-health, realtime-audio\n\n";

        out << H2("COMMON FACETS") << "\n";
        out << "  sensors, queue, startup, scheduledtasks, smart, events, shutdown, whea\n";
        out << Dim("Note: facets are collector-specific; unknown facets are ignored by unrelated topics.") << "\n\n";

        out << H2("BEHAVIOR NOTES") << "\n";
        out << "  - Non-admin runs are allowed: restricted sources emit permission findings.\n";
        out << "  - Timeout and budget decisions are reported in output (skipped/denied/timed_out).\n";
        out << "  - For deterministic machine parsing, prefer " << Flag("--format tagged") << ".\n\n";

        out << H2("EXAMPLES") << "\n";
        out << "  sysinf topic --target thermal\n";
        out << "  sysinf topic --target thermal,io-latency --include sensors,queue --since 2h\n";
        out << "  sysinf topic --target startup-impact --exclude scheduledtasks\n";
        out << "  sysinf topic --target gpu-telemetry --level deep --sources perfcounter.gpu,wmi.thermalzone\n";
        out << "  sysinf topic --target services-health,eventlog --format tagged --token-mode economy\n";
        return out.str();
    }

    out << H2("USAGE") << "\n";
    out << "  sysinf " << sub << " [global options]\n";
    return out.str();
}
