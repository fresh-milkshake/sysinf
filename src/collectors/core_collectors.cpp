#include "collectors.h"

#include <windows.h>

#include <filesystem>

#include "collectors/common.h"
#include "util.h"

using collectors_internal::AddPartial;
using collectors_internal::AddProbe;
using collectors_internal::Evt;
using collectors_internal::Meta;
using collectors_internal::Mk;
using collectors_internal::Ps;

CollectorResult SystemCollector::Collect(Context& context) const {
    CollectorResult r;
    r.collector_id = "system_baseline";
    Meta(context, &r);

    AddProbe(context, &r, "sys.os.baseline", "OS baseline captured", "Windows baseline info captured.", "cim.os",
             Ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime | Format-List"), false, false, 12);

    const unsigned long long uptime_ms = static_cast<unsigned long long>(GetTickCount64());
    const double uptime_hours = static_cast<double>(uptime_ms) / (1000.0 * 60.0 * 60.0);
    r.findings.push_back(Mk("sys.uptime", "System uptime", "Estimated uptime hours: " + std::to_string(static_cast<int>(uptime_hours)),
                            uptime_hours < 1.0 ? Severity::kWarning : Severity::kInfo, 0.9, "winapi.gettickcount64"));

    if (context.command == Command::kSummary) {
        auto hint = Mk("summary.targeted_hint", "Summary kept lightweight by design",
                       "Use 'topic --target ...' with filters for deeper diagnostics.", Severity::kInfo, 0.99, "sysinf.policy");
        hint.metadata["category"] = "summary_policy";
        r.findings.push_back(hint);
    }

    AddPartial(context, &r);
    return r;
}

CollectorResult HardwareCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "hardware_inventory";
    Meta(c, &r);

    AddProbe(c, &r, "hw.cpu", "CPU inventory", "CPU inventory captured.", "cim.cpu",
             Ps("Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Format-List"), false, false, 14, "cpu");
    AddProbe(c, &r, "hw.memory", "Memory inventory", "Memory inventory captured.", "cim.memory",
             Ps("Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,ConfiguredClockSpeed,Capacity,PartNumber | Format-Table -AutoSize"), false, false, 16, "memory");
    AddProbe(c, &r, "hw.gpu", "GPU inventory", "GPU inventory captured.", "cim.gpu",
             Ps("Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM | Format-List"), false, false, 14, "gpu");
    AddProbe(c, &r, "hw.audio", "Audio inventory", "Audio inventory captured.", "cim.audio",
             Ps("Get-CimInstance Win32_SoundDevice | Select-Object Name,Status,Manufacturer | Format-Table -AutoSize"), false, false, 16, "audio");

    AddPartial(c, &r);
    return r;
}

CollectorResult StorageCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "storage_health";
    Meta(c, &r);

    AddProbe(c, &r, "storage.disk_inventory", "Disk inventory", "Physical disk inventory captured.", "cim.diskdrive",
             Ps("Get-CimInstance Win32_DiskDrive | Select-Object Model,SerialNumber,Size,Status,InterfaceType | Format-Table -AutoSize"), false, false, 16, "storage");
    AddProbe(c, &r, "storage.health.surface", "Storage health surface", "Storage health indicators captured.", "storage.smart",
             Ps("Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus,MediaType,Size | Format-Table -AutoSize"), true, true, 16, "smart");

    const std::string since = BuildPowerShellSinceExpression(c.since);
    AddProbe(c, &r, "storage.event_signals", "Storage event signals", "Storage-related event signals captured.", "eventlog.storage",
             Evt("System", "7,51,129,153", since, c.max_events), false, false, 24, "events");

    AddPartial(c, &r);
    return r;
}

CollectorResult PowerCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "power_thermal_shutdown";
    Meta(c, &r);

    const std::string since = BuildPowerShellSinceExpression(c.since);
    AddProbe(c, &r, "power.shutdown_events", "Unexpected shutdown/reboot signals", "Power shutdown/reboot events captured.", "eventlog.power",
             Evt("System", "41,6008,6005,6006", since, c.max_events), false, false, 28, "shutdown");
    AddProbe(c, &r, "power.whea", "Hardware error signals (WHEA)", "WHEA events captured.", "eventlog.whea",
             Evt("System", "18,19,20,46,47", since, c.max_events), false, false, 24, "whea");

    AddPartial(c, &r);
    return r;
}

CollectorResult CrashCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "crash_bsod_metadata";
    Meta(c, &r);

    const std::string since = BuildPowerShellSinceExpression(c.since);
    AddProbe(c, &r, "crash.bugcheck_events", "BugCheck events", "BugCheck events captured.", "eventlog.bugcheck",
             Evt("System", "1001", since, c.max_events), false, false, 24);
    AddProbe(c, &r, "crash.crashcontrol_registry", "CrashControl registry", "Crash dump policy keys captured.", "registry.crashcontrol",
             "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl", false, true, 20);

    const std::filesystem::path dumps = "C:\\Windows\\Minidump";
    r.findings.push_back(Mk("crash.minidump_presence", "Minidump presence",
                            std::filesystem::exists(dumps) ? "Minidump directory exists." : "Minidump directory missing.",
                            std::filesystem::exists(dumps) ? Severity::kInfo : Severity::kWarning, 0.95, "filesystem.minidump"));

    AddPartial(c, &r);
    return r;
}

CollectorResult DeviceCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "device_diagnostics";
    Meta(c, &r);

    AddProbe(c, &r, "device.inventory", "PnP device inventory snapshot", "PnP snapshot captured.", "cim.pnp",
             Ps("Get-CimInstance Win32_PnPEntity | Select-Object Name,Status,PNPClass,Manufacturer | Format-Table -AutoSize"), false, false, 28);

    AddPartial(c, &r);
    return r;
}

CollectorResult LogCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "event_log_focus";
    Meta(c, &r);

    const std::string since = BuildPowerShellSinceExpression(c.since);
    AddProbe(c, &r, "logs.system", "System log sample", "System log events collected.", "eventlog.system",
             Ps("$s=" + since + "; Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$s} -MaxEvents " + std::to_string(c.max_events) +
                " | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List"), false, false, 28);
    AddProbe(c, &r, "logs.application", "Application log sample", "Application log events collected.", "eventlog.application",
             Ps("$s=" + since + "; Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$s} -MaxEvents " + std::to_string(c.max_events) +
                " | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List"), false, false, 28);

    AddPartial(c, &r);
    return r;
}

const char* SystemCollector::DisplayName() const { return "System Baseline"; }
const char* HardwareCollector::DisplayName() const { return "Hardware Inventory"; }
const char* StorageCollector::DisplayName() const { return "Storage Health"; }
const char* PowerCollector::DisplayName() const { return "Power/Thermal/Shutdown"; }
const char* CrashCollector::DisplayName() const { return "Crash/BSOD Metadata"; }
const char* DeviceCollector::DisplayName() const { return "Device Diagnostics"; }
const char* LogCollector::DisplayName() const { return "Event Logs"; }
