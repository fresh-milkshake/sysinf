#ifndef SYSINF_OUTPUT_H
#define SYSINF_OUTPUT_H

#include <string>
#include <vector>

#include "types.h"

std::string RenderReport(const Context& context, const std::vector<CollectorResult>& results);
bool HasHighPriorityFindings(const std::vector<CollectorResult>& results);

#endif
