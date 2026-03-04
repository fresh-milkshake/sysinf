#ifndef SYSINF_CLI_H
#define SYSINF_CLI_H

#include <string>
#include <vector>

#include "types.h"

struct ParseResult {
    bool ok = false;
    bool show_help = false;
    std::string error;
    Context context;
};

ParseResult ParseCli(int argc, char** argv);
std::string BuildHelpText(const std::string& subcommand = "");

#endif
