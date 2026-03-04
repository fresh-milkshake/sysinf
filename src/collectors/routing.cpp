#include "collectors.h"

#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#include "util.h"

namespace {

enum class CollectorKey {
    kSystem,
    kHardware,
    kStorage,
    kPower,
    kCrash,
    kDevice,
    kLog,
    kThermal,
    kProcesses,
    kScheduler,
    kMemoryPressure,
    kIoLatency,
    kDiskQueue,
    kGpuTelemetry,
    kPowerPolicy,
    kInterrupts,
    kStartupImpact,
    kServicesHealth,
    kRealtimeAudio,
};

std::unique_ptr<ICollector> MakeCollector(CollectorKey key) {
    switch (key) {
        case CollectorKey::kSystem:
            return std::make_unique<SystemCollector>();
        case CollectorKey::kHardware:
            return std::make_unique<HardwareCollector>();
        case CollectorKey::kStorage:
            return std::make_unique<StorageCollector>();
        case CollectorKey::kPower:
            return std::make_unique<PowerCollector>();
        case CollectorKey::kCrash:
            return std::make_unique<CrashCollector>();
        case CollectorKey::kDevice:
            return std::make_unique<DeviceCollector>();
        case CollectorKey::kLog:
            return std::make_unique<LogCollector>();
        case CollectorKey::kThermal:
            return std::make_unique<ThermalCollector>();
        case CollectorKey::kProcesses:
            return std::make_unique<ProcessPressureCollector>();
        case CollectorKey::kScheduler:
            return std::make_unique<SchedulerCollector>();
        case CollectorKey::kMemoryPressure:
            return std::make_unique<MemoryPressureCollector>();
        case CollectorKey::kIoLatency:
            return std::make_unique<IoLatencyCollector>();
        case CollectorKey::kDiskQueue:
            return std::make_unique<DiskQueueCollector>();
        case CollectorKey::kGpuTelemetry:
            return std::make_unique<GpuTelemetryCollector>();
        case CollectorKey::kPowerPolicy:
            return std::make_unique<PowerPolicyCollector>();
        case CollectorKey::kInterrupts:
            return std::make_unique<InterruptCollector>();
        case CollectorKey::kStartupImpact:
            return std::make_unique<StartupImpactCollector>();
        case CollectorKey::kServicesHealth:
            return std::make_unique<ServicesHealthCollector>();
        case CollectorKey::kRealtimeAudio:
            return std::make_unique<RealtimeAudioCollector>();
    }
    return std::make_unique<SystemCollector>();
}

const std::unordered_map<std::string, std::vector<CollectorKey>>& TopicRegistry() {
    static const std::unordered_map<std::string, std::vector<CollectorKey>> kRegistry = {
        {"thermal", {CollectorKey::kThermal}},
        {"processes", {CollectorKey::kProcesses}},
        {"scheduler", {CollectorKey::kScheduler}},
        {"memory-pressure", {CollectorKey::kMemoryPressure}},
        {"io-latency", {CollectorKey::kIoLatency}},
        {"disk-queue", {CollectorKey::kDiskQueue}},
        {"gpu-telemetry", {CollectorKey::kGpuTelemetry}},
        {"power-policy", {CollectorKey::kPowerPolicy}},
        {"interrupts", {CollectorKey::kInterrupts}},
        {"startup-impact", {CollectorKey::kStartupImpact}},
        {"services-health", {CollectorKey::kServicesHealth}},
        {"realtime-audio", {CollectorKey::kRealtimeAudio}},
        {"cpu", {CollectorKey::kHardware}},
        {"memory", {CollectorKey::kHardware}},
        {"gpu", {CollectorKey::kHardware}},
        {"audio", {CollectorKey::kHardware}},
        {"storage", {CollectorKey::kStorage}},
        {"power", {CollectorKey::kPower}},
        {"network", {CollectorKey::kDevice}},
        {"drivers", {CollectorKey::kDevice}},
        {"eventlog", {CollectorKey::kLog}},
        {"crash", {CollectorKey::kCrash}},
    };
    return kRegistry;
}

const std::unordered_map<std::string, std::vector<CollectorKey>>& IncidentRegistry() {
    static const std::unordered_map<std::string, std::vector<CollectorKey>> kRegistry = {
        {"sound", {CollectorKey::kSystem, CollectorKey::kRealtimeAudio, CollectorKey::kStorage, CollectorKey::kDevice}},
        {"shutdown", {CollectorKey::kSystem, CollectorKey::kPower, CollectorKey::kStorage, CollectorKey::kCrash}},
        {"crash", {CollectorKey::kSystem, CollectorKey::kCrash, CollectorKey::kDevice}},
        {"device", {CollectorKey::kSystem, CollectorKey::kDevice, CollectorKey::kServicesHealth}},
    };
    return kRegistry;
}

const std::map<Command, std::vector<CollectorKey>>& CommandProfiles() {
    static const std::map<Command, std::vector<CollectorKey>> kProfiles = {
        {Command::kSummary, {CollectorKey::kSystem, CollectorKey::kHardware, CollectorKey::kStorage, CollectorKey::kPower, CollectorKey::kServicesHealth}},
        {Command::kHardware, {CollectorKey::kHardware, CollectorKey::kDevice}},
        {Command::kLogs, {CollectorKey::kLog}},
        {Command::kCrash, {CollectorKey::kCrash, CollectorKey::kPower}},
    };
    return kProfiles;
}

void AppendKeys(const std::vector<CollectorKey>& keys, std::vector<std::unique_ptr<ICollector>>* out) {
    for (const auto key : keys) {
        out->push_back(MakeCollector(key));
    }
}

}  // namespace

std::vector<std::unique_ptr<ICollector>> BuildCollectorsForContext(const Context& context) {
    std::vector<std::unique_ptr<ICollector>> out;

    const auto& profiles = CommandProfiles();
    const auto profile_it = profiles.find(context.command);
    if (profile_it != profiles.end()) {
        AppendKeys(profile_it->second, &out);
    } else if (context.command == Command::kIncident) {
        const auto& incidents = IncidentRegistry();
        const auto incident_it = incidents.find(ToLower(context.sub_target));
        if (incident_it != incidents.end()) {
            AppendKeys(incident_it->second, &out);
        }
    } else if (context.command == Command::kTopic) {
        const auto& topics = TopicRegistry();
        std::set<std::string> uniq;
        std::vector<std::string> targets = context.requested_topics;
        if (targets.empty() && !context.sub_target.empty()) {
            targets.push_back(context.sub_target);
        }

        for (const auto& topic : targets) {
            if (!uniq.insert(topic).second) {
                continue;
            }
            const auto it = topics.find(topic);
            if (it != topics.end()) {
                AppendKeys(it->second, &out);
            }
        }
    }

    if (out.empty()) {
        out.emplace_back(std::make_unique<SystemCollector>());
    }
    return out;
}
