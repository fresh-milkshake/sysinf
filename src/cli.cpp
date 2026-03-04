#include "cli.h"

#include <algorithm>
#include <sstream>

#include "util.h"

namespace {

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
        };
        if (ctx.sub_target.empty()) {
            *error = "topic requires --target <cpu|memory|storage|gpu|audio|power|network|drivers|eventlog|crash>.";
            return false;
        }
        if (std::find(topics.begin(), topics.end(), ToLower(ctx.sub_target)) == topics.end()) {
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

        if (arg == "--preset" || arg == "--target" || arg == "--device-class") {
            if (i + 1 >= args.size()) {
                result.error = "Missing value for " + arg;
                return result;
            }
            result.context.sub_target = ToLower(args[i + 1]);
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
        out << "sysinf.exe - Windows Incident Diagnostics CLI (AI-first)\n\n";
        out << "USAGE:\n";
        out << "  sysinf <subcommand> [options]\n\n";
        out << "SUBCOMMANDS:\n";
        out << "  summary   Wide precheck snapshot across system and hardware\n";
        out << "  incident  Preset-focused deep diagnostics\n";
        out << "  hardware  Device and driver-oriented hardware diagnostics\n";
        out << "  logs      Event log diagnostics (System/Application focus)\n";
        out << "  crash     Crash/BSOD metadata diagnostics\n";
        out << "  topic     Targeted diagnostics by topic\n\n";
        out << "GLOBAL OPTIONS:\n";
        out << "  --verbosity <0..5>         Default: 1\n";
        out << "  --format <pretty|tagged>   Default: pretty\n";
        out << "  --token-mode <normal|economy>  Default: normal\n";
        out << "  --since <duration|datetime> Default: 24h (examples: 6h, 2d, 2026-03-01T00:00:00)\n";
        out << "  --max-events <N>           Default: 100\n";
        out << "  --no-color                 Disable ANSI coloring in pretty mode\n\n";
        out << "INCIDENT PRESETS:\n";
        out << "  sound, shutdown, crash, device\n\n";
        out << "TOPIC TARGETS:\n";
        out << "  cpu, memory, storage, gpu, audio, power, network, drivers, eventlog, crash\n\n";
        out << "EXAMPLES:\n";
        out << "  sysinf summary --verbosity 1\n";
        out << "  sysinf incident --preset shutdown --since 48h --max-events 200\n";
        out << "  sysinf incident --preset sound --format tagged --token-mode economy\n";
        out << "  sysinf topic --target storage --verbosity 4\n";
        out << "  sysinf logs --since 2026-03-01T00:00:00 --max-events 300\n\n";
        out << "EXIT CODES:\n";
        out << "  0  Successful run with no high-priority findings\n";
        out << "  1  Any warning/critical/error finding OR runtime collection problem\n";
        return out.str();
    }

    if (sub == "incident") {
        out << "USAGE:\n";
        out << "  sysinf incident --preset <sound|shutdown|crash|device> [global options]\n\n";
        out << "DESCRIPTION:\n";
        out << "  Runs incident-specific diagnostics and prints likely causes + next checks.\n";
        return out.str();
    }

    if (sub == "topic") {
        out << "USAGE:\n";
        out << "  sysinf topic --target <cpu|memory|storage|gpu|audio|power|network|drivers|eventlog|crash> [global options]\n\n";
        out << "DESCRIPTION:\n";
        out << "  Runs a focused collector set for the selected troubleshooting topic.\n";
        return out.str();
    }

    out << "USAGE:\n";
    out << "  sysinf " << sub << " [global options]\n";
    return out.str();
}
