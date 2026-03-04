#ifndef SYSINF_COLLECTORS_COMMON_H
#define SYSINF_COLLECTORS_COMMON_H

#include <string>
#include <vector>

#include "collectors.h"

namespace collectors_internal {

Finding Mk(const std::string& id,
           const std::string& title,
           const std::string& sum,
           Severity sev,
           double conf,
           const std::string& src);

std::string Ps(const std::string& body);
std::string Evt(const std::string& log_name, const std::string& ids_csv, const std::string& since_expr, int max_events);

void Meta(const Context& c, CollectorResult* r);
void AddPartial(Context& c, CollectorResult* r);

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
              const std::string& facet = "");

}  // namespace collectors_internal

#endif
