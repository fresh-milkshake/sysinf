#ifndef SYSINF_COLLECTORS_H
#define SYSINF_COLLECTORS_H

#include <memory>
#include <string>
#include <vector>

#include "types.h"

class ICollector {
public:
    virtual ~ICollector() = default;
    virtual CollectorResult Collect(const Context& context) const = 0;
    virtual const char* DisplayName() const = 0;
};

class SystemCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

class HardwareCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

class StorageCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

class PowerCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

class CrashCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

class DeviceCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

class LogCollector : public ICollector {
public:
    CollectorResult Collect(const Context& context) const override;
    const char* DisplayName() const override;
};

std::vector<std::unique_ptr<ICollector>> BuildCollectorsForContext(const Context& context);

#endif
