#include "collectors.h"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <sstream>

#include "util.h"

namespace {

Finding MakeFinding(const std::string& id,
                    const std::string& title,
                    const std::string& summary,
                    Severity severity,
                    double confidence,
                    const std::string& source) {
    Finding finding;
    finding.id = id;
    finding.title = title;
    finding.summary = summary;
    finding.severity = severity;
    finding.confidence = confidence;
    finding.source = source;
    return finding;
}

std::vector<std::string> NonEmptyLines(const std::string& raw, size_t max_lines) {
    std::vector<std::string> lines;
    for (const auto& line : SplitLines(raw)) {
        if (line.empty()) {
            continue;
        }
        lines.push_back(line);
        if (lines.size() >= max_lines) {
            break;
        }
    }
    return lines;
}

std::string JoinForSummary(const std::vector<std::string>& lines) {
    if (lines.empty()) {
        return "No data returned.";
    }
    if (lines.size() == 1) {
        return lines[0];
    }
    return lines[0] + " | " + lines[1];
}

Finding MakeCommandFailureFinding(const std::string& id, const std::string& source, const std::string& command, int exit_code) {
    auto finding = MakeFinding(
        id,
        "Data source execution failure",
        "A required data-source command failed and reduced diagnostic confidence.",
        Severity::kWarning,
        0.95,
        source);
    finding.evidence.push_back("command=" + command);
    finding.evidence.push_back("exit_code=" + std::to_string(exit_code));
    finding.likely_causes.push_back("Permission or provider issues in host environment.");
    finding.next_checks.push_back("Re-run as elevated admin in a standard Windows shell.");
    return finding;
}

std::string PowershellWrap(const std::string& body) {
    return "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + body + "\"";
}

std::string EventQueryPs(const std::string& log_name,
                         const std::string& ids_csv,
                         const std::string& since_expr,
                         int max_events) {
    std::ostringstream q;
    q << "$s=" << since_expr << "; "
      << "Get-WinEvent -FilterHashtable @{LogName='" << log_name << "'; Id=" << ids_csv << "; StartTime=$s} "
      << "-MaxEvents " << max_events << " "
      << "| Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message "
      << "| Format-List";
    return PowershellWrap(q.str());
}

}  // namespace

CollectorResult SystemCollector::Collect(const Context& context) const {
    CollectorResult result;
    result.collector_id = "system_baseline";

    result.metadata["since"] = context.since;
    result.metadata["verbosity"] = std::to_string(context.verbosity);

    int code = 0;
    const std::string os_info = RunCommand(
        PowershellWrap("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime | Format-List"),
        &code);
    if (code != 0) {
        result.findings.push_back(MakeCommandFailureFinding("sys.source.os.cim_failed", "cim/win32_operatingsystem", "Get-CimInstance Win32_OperatingSystem", code));
    } else {
        auto finding = MakeFinding(
            "sys.os.baseline",
            "OS baseline captured",
            "Windows baseline info captured successfully.",
            Severity::kInfo,
            0.98,
            "cim/win32_operatingsystem");
        finding.evidence = NonEmptyLines(os_info, 12);
        result.findings.push_back(finding);
    }

    code = 0;
    const std::string cs_info = RunCommand(
        PowershellWrap("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory | Format-List"),
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "sys.platform.baseline",
            "Platform baseline captured",
            JoinForSummary(NonEmptyLines(cs_info, 4)),
            Severity::kInfo,
            0.95,
            "cim/win32_computersystem");
        finding.evidence = NonEmptyLines(cs_info, 8);
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("sys.source.cs.cim_failed", "cim/win32_computersystem", "Get-CimInstance Win32_ComputerSystem", code));
    }

    const unsigned long long uptime_ms = static_cast<unsigned long long>(GetTickCount64());
    const double uptime_hours = static_cast<double>(uptime_ms) / (1000.0 * 60.0 * 60.0);
    auto uptime_finding = MakeFinding(
        "sys.uptime",
        "System uptime",
        "Estimated uptime hours: " + std::to_string(static_cast<int>(uptime_hours)),
        uptime_hours < 1.0 ? Severity::kWarning : Severity::kInfo,
        0.9,
        "winapi/gettickcount64");
    if (uptime_hours < 1.0) {
        uptime_finding.likely_causes.push_back("Recent reboot or unstable reboot loop.");
        uptime_finding.next_checks.push_back("Correlate with Kernel-Power and EventID 6008 in logs.");
    }
    result.findings.push_back(uptime_finding);

    return result;
}

CollectorResult HardwareCollector::Collect(const Context& context) const {
    (void)context;
    CollectorResult result;
    result.collector_id = "hardware_inventory";

    struct Query {
        std::string id;
        std::string title;
        std::string source;
        std::string command;
    };

    const std::vector<Query> queries = {
        {"hw.cpu", "CPU inventory", "cim/win32_processor", PowershellWrap("Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Format-List")},
        {"hw.memory", "Memory inventory", "cim/win32_physicalmemory", PowershellWrap("Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,ConfiguredClockSpeed,Capacity,PartNumber | Format-Table -AutoSize")},
        {"hw.gpu", "GPU inventory", "cim/win32_videocontroller", PowershellWrap("Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM | Format-List")},
        {"hw.board_bios", "Motherboard/BIOS inventory", "cim/win32_baseboard+win32_bios", PowershellWrap("Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,SerialNumber | Format-List; Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion,ReleaseDate | Format-List")},
        {"hw.audio", "Audio device inventory", "cim/win32_sounddevice", PowershellWrap("Get-CimInstance Win32_SoundDevice | Select-Object Name,Status,Manufacturer | Format-Table -AutoSize")},
    };

    for (const auto& query : queries) {
        int code = 0;
        const std::string output = RunCommand(query.command, &code);
        if (code != 0) {
            result.findings.push_back(MakeCommandFailureFinding(query.id + ".source_failed", query.source, query.command, code));
            continue;
        }

        auto finding = MakeFinding(query.id, query.title, "Inventory data captured.", Severity::kInfo, 0.92, query.source);
        finding.evidence = NonEmptyLines(output, 16);
        result.findings.push_back(finding);
    }

    return result;
}

CollectorResult StorageCollector::Collect(const Context& context) const {
    CollectorResult result;
    result.collector_id = "storage_health";

    int code = 0;
    const std::string disks = RunCommand(
        PowershellWrap("Get-CimInstance Win32_DiskDrive | Select-Object Model,SerialNumber,Size,Status,InterfaceType | Format-Table -AutoSize"),
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "storage.disk_inventory",
            "Disk inventory",
            "Physical disk inventory captured.",
            Severity::kInfo,
            0.9,
            "cim/win32_diskdrive");
        finding.evidence = NonEmptyLines(disks, 18);
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("storage.disk_inventory.source_failed", "cim/win32_diskdrive", "Get-CimInstance Win32_DiskDrive", code));
    }

    code = 0;
    const std::string smart = RunCommand(
        PowershellWrap("Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus,MediaType,Size | Format-Table -AutoSize"),
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "storage.health.surface",
            "Storage health surface",
            "Storage subsystem health indicators collected.",
            Severity::kInfo,
            0.75,
            "powershell/get-physicaldisk");
        finding.evidence = NonEmptyLines(smart, 18);
        finding.next_checks.push_back("If unavailable/empty, use vendor SMART tools for direct NVMe/SATA telemetry.");
        result.findings.push_back(finding);
    } else {
        auto finding = MakeCommandFailureFinding("storage.health.surface.source_failed", "powershell/get-physicaldisk", "Get-PhysicalDisk", code);
        finding.next_checks.push_back("Fallback to vendor-specific SMART utility (CrystalDiskInfo, smartctl, OEM tool). ");
        result.findings.push_back(finding);
    }

    const std::string since_expr = BuildPowerShellSinceExpression(context.since);
    code = 0;
    const std::string io_events = RunCommand(
        EventQueryPs("System", "7,51,129,153", since_expr, context.max_events),
        &code);
    if (code == 0) {
        const auto lines = NonEmptyLines(io_events, 32);
        auto finding = MakeFinding(
            "storage.event_signals",
            "Storage-related event signals",
            lines.empty() ? "No matching storage warning/error events in selected time window." : "Storage-related events were found in the selected time window.",
            lines.empty() ? Severity::kInfo : Severity::kWarning,
            0.86,
            "eventlog/system");
        finding.evidence = lines;
        if (!lines.empty()) {
            finding.likely_causes.push_back("Controller or device timeout/reset behavior (Event IDs 129/153/51/7). ");
            finding.next_checks.push_back("Check SATA/NVMe cabling, controller firmware, and drive health at vendor level.");
        }
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("storage.event_signals.source_failed", "eventlog/system", "Get-WinEvent System IDs 7,51,129,153", code));
    }

    return result;
}

CollectorResult PowerCollector::Collect(const Context& context) const {
    CollectorResult result;
    result.collector_id = "power_thermal_shutdown";

    const std::string since_expr = BuildPowerShellSinceExpression(context.since);
    int code = 0;
    const std::string power_events = RunCommand(
        EventQueryPs("System", "41,6008,6005,6006", since_expr, context.max_events),
        &code);

    if (code == 0) {
        const auto lines = NonEmptyLines(power_events, 36);
        bool has_kernel_power = false;
        bool has_6008 = false;
        for (const auto& line : lines) {
            if (line.find("Id               : 41") != std::string::npos) {
                has_kernel_power = true;
            }
            if (line.find("Id               : 6008") != std::string::npos) {
                has_6008 = true;
            }
        }

        auto finding = MakeFinding(
            "power.shutdown_events",
            "Unexpected shutdown/reboot signals",
            lines.empty() ? "No power/shutdown events found in selected window." : "Power-related events detected.",
            (has_kernel_power || has_6008) ? Severity::kCritical : Severity::kInfo,
            0.9,
            "eventlog/system");
        finding.evidence = lines;
        if (has_kernel_power || has_6008) {
            finding.likely_causes.push_back("Power instability, PSU issues, thermal protection, or forced reset path.");
            finding.next_checks.push_back("Inspect PSU rails, CPU/GPU temperatures, and motherboard power connectors.");
            finding.next_checks.push_back("Correlate timestamps with heavy load or thermal spikes.");
        }
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("power.shutdown_events.source_failed", "eventlog/system", "Get-WinEvent System IDs 41,6008,6005,6006", code));
    }

    code = 0;
    const std::string whea = RunCommand(
        EventQueryPs("System", "18,19,20,46,47", since_expr, context.max_events),
        &code);
    if (code == 0) {
        const auto lines = NonEmptyLines(whea, 28);
        auto finding = MakeFinding(
            "power.whea",
            "Hardware error signals (WHEA)",
            lines.empty() ? "No WHEA hardware error events detected." : "WHEA hardware error events detected.",
            lines.empty() ? Severity::kInfo : Severity::kWarning,
            0.85,
            "eventlog/system");
        finding.evidence = lines;
        if (!lines.empty()) {
            finding.likely_causes.push_back("CPU, memory, PCIe, or power delivery instability.");
            finding.next_checks.push_back("Run memory and CPU stress diagnostics; verify BIOS stability settings.");
        }
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("power.whea.source_failed", "eventlog/system", "Get-WinEvent System WHEA IDs", code));
    }

    return result;
}

CollectorResult CrashCollector::Collect(const Context& context) const {
    CollectorResult result;
    result.collector_id = "crash_bsod_metadata";

    const std::string since_expr = BuildPowerShellSinceExpression(context.since);

    int code = 0;
    const std::string bugcheck_events = RunCommand(
        EventQueryPs("System", "1001", since_expr, context.max_events),
        &code);
    if (code == 0) {
        const auto lines = NonEmptyLines(bugcheck_events, 30);
        auto finding = MakeFinding(
            "crash.bugcheck_events",
            "BugCheck / system error reporting events",
            lines.empty() ? "No BugCheck-related events found." : "BugCheck-related events found.",
            lines.empty() ? Severity::kInfo : Severity::kCritical,
            0.87,
            "eventlog/system");
        finding.evidence = lines;
        if (!lines.empty()) {
            finding.likely_causes.push_back("Kernel crash path detected by Windows Error Reporting.");
            finding.next_checks.push_back("Correlate BugCheck timestamps with recent driver/hardware changes.");
        }
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("crash.bugcheck_events.source_failed", "eventlog/system", "Get-WinEvent System ID 1001", code));
    }

    code = 0;
    const std::string wer = RunCommand(
        EventQueryPs("Application", "1000,1001,1002", since_expr, context.max_events),
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "crash.wer_app",
            "Application crash surface (WER)",
            "Application-level crash telemetry sampled from Application log.",
            Severity::kInfo,
            0.7,
            "eventlog/application");
        finding.evidence = NonEmptyLines(wer, 24);
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("crash.wer_app.source_failed", "eventlog/application", "Get-WinEvent Application IDs 1000,1001,1002", code));
    }

    const std::filesystem::path minidump_dir = "C:\\Windows\\Minidump";
    if (std::filesystem::exists(minidump_dir)) {
        std::vector<std::filesystem::directory_entry> dumps;
        for (const auto& entry : std::filesystem::directory_iterator(minidump_dir)) {
            if (entry.is_regular_file()) {
                dumps.push_back(entry);
            }
        }
        std::sort(dumps.begin(), dumps.end(), [](const auto& a, const auto& b) {
            return a.last_write_time() > b.last_write_time();
        });

        auto finding = MakeFinding(
            "crash.minidump_presence",
            "Minidump presence",
            "Found " + std::to_string(dumps.size()) + " dump files in C:\\Windows\\Minidump.",
            dumps.empty() ? Severity::kWarning : Severity::kInfo,
            0.95,
            "filesystem/minidump");
        if (!dumps.empty()) {
            const auto newest = dumps.front().path().filename().string();
            finding.evidence.push_back("newest_dump=" + newest);
        } else {
            finding.likely_causes.push_back("Crash dump generation may be disabled or failing.");
            finding.next_checks.push_back("Check CrashControl registry and paging file settings.");
        }
        result.findings.push_back(finding);
    } else {
        auto finding = MakeFinding(
            "crash.minidump_missing",
            "Minidump directory missing",
            "C:\\Windows\\Minidump does not exist.",
            Severity::kWarning,
            0.9,
            "filesystem/minidump");
        finding.next_checks.push_back("Confirm crash dump policy under HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl.");
        result.findings.push_back(finding);
    }

    code = 0;
    const std::string crash_control = RunCommand(
        "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl",
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "crash.crashcontrol_registry",
            "CrashControl registry",
            "Crash dump policy registry keys captured.",
            Severity::kInfo,
            0.95,
            "registry/crashcontrol");
        finding.evidence = NonEmptyLines(crash_control, 20);
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("crash.crashcontrol_registry.source_failed", "registry/crashcontrol", "reg query CrashControl", code));
    }

    return result;
}

CollectorResult DeviceCollector::Collect(const Context& context) const {
    CollectorResult result;
    result.collector_id = "device_diagnostics";

    const std::string lower_target = ToLower(context.sub_target);
    std::string class_filter;
    if (!lower_target.empty() && lower_target != "device") {
        class_filter = lower_target;
    }

    int code = 0;
    const std::string pnp = RunCommand(
        PowershellWrap("Get-CimInstance Win32_PnPEntity | Select-Object Name,Status,PNPClass,Manufacturer | Format-Table -AutoSize"),
        &code);
    if (code != 0) {
        result.findings.push_back(MakeCommandFailureFinding("device.pnp_inventory.source_failed", "cim/win32_pnpentity", "Get-CimInstance Win32_PnPEntity", code));
        return result;
    }

    std::vector<std::string> filtered;
    for (const auto& line : NonEmptyLines(pnp, 500)) {
        if (!class_filter.empty()) {
            if (ToLower(line).find(class_filter) == std::string::npos) {
                continue;
            }
        }
        filtered.push_back(line);
        if (filtered.size() >= 40) {
            break;
        }
    }

    auto finding = MakeFinding(
        "device.inventory",
        "PnP device inventory snapshot",
        filtered.empty() ? "No matching device lines in selected filter." : "PnP snapshot captured.",
        filtered.empty() ? Severity::kWarning : Severity::kInfo,
        0.8,
        "cim/win32_pnpentity");
    finding.evidence = filtered;
    if (filtered.empty() && !class_filter.empty()) {
        finding.likely_causes.push_back("Selected device-class filter is too narrow or class string mismatch.");
        finding.next_checks.push_back("Run without --device-class or use broader values (audio, storage, net, display). ");
    }
    result.findings.push_back(finding);

    return result;
}

CollectorResult LogCollector::Collect(const Context& context) const {
    CollectorResult result;
    result.collector_id = "event_log_focus";

    const std::string since_expr = BuildPowerShellSinceExpression(context.since);

    int code = 0;
    const std::string system = RunCommand(
        PowershellWrap("$s=" + since_expr + "; Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$s} -MaxEvents " +
                       std::to_string(context.max_events) +
                       " | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List"),
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "logs.system",
            "System log sample",
            "System log events collected.",
            Severity::kInfo,
            0.8,
            "eventlog/system");
        finding.evidence = NonEmptyLines(system, 35);
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("logs.system.source_failed", "eventlog/system", "Get-WinEvent System", code));
    }

    code = 0;
    const std::string app = RunCommand(
        PowershellWrap("$s=" + since_expr + "; Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$s} -MaxEvents " +
                       std::to_string(context.max_events) +
                       " | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List"),
        &code);
    if (code == 0) {
        auto finding = MakeFinding(
            "logs.application",
            "Application log sample",
            "Application log events collected.",
            Severity::kInfo,
            0.8,
            "eventlog/application");
        finding.evidence = NonEmptyLines(app, 35);
        result.findings.push_back(finding);
    } else {
        result.findings.push_back(MakeCommandFailureFinding("logs.application.source_failed", "eventlog/application", "Get-WinEvent Application", code));
    }

    return result;
}

std::vector<std::unique_ptr<ICollector>> BuildCollectorsForContext(const Context& context) {
    std::vector<std::unique_ptr<ICollector>> collectors;

    switch (context.command) {
        case Command::kSummary:
            collectors.emplace_back(std::make_unique<SystemCollector>());
            collectors.emplace_back(std::make_unique<HardwareCollector>());
            collectors.emplace_back(std::make_unique<StorageCollector>());
            collectors.emplace_back(std::make_unique<PowerCollector>());
            collectors.emplace_back(std::make_unique<CrashCollector>());
            break;
        case Command::kIncident: {
            const std::string preset = ToLower(context.sub_target);
            collectors.emplace_back(std::make_unique<SystemCollector>());
            if (preset == "sound") {
                collectors.emplace_back(std::make_unique<HardwareCollector>());
                collectors.emplace_back(std::make_unique<StorageCollector>());
                collectors.emplace_back(std::make_unique<DeviceCollector>());
                collectors.emplace_back(std::make_unique<LogCollector>());
            } else if (preset == "shutdown") {
                collectors.emplace_back(std::make_unique<PowerCollector>());
                collectors.emplace_back(std::make_unique<StorageCollector>());
                collectors.emplace_back(std::make_unique<CrashCollector>());
            } else if (preset == "crash") {
                collectors.emplace_back(std::make_unique<CrashCollector>());
                collectors.emplace_back(std::make_unique<PowerCollector>());
                collectors.emplace_back(std::make_unique<DeviceCollector>());
            } else if (preset == "device") {
                collectors.emplace_back(std::make_unique<DeviceCollector>());
                collectors.emplace_back(std::make_unique<HardwareCollector>());
                collectors.emplace_back(std::make_unique<LogCollector>());
            }
            break;
        }
        case Command::kHardware:
            collectors.emplace_back(std::make_unique<HardwareCollector>());
            collectors.emplace_back(std::make_unique<DeviceCollector>());
            collectors.emplace_back(std::make_unique<StorageCollector>());
            break;
        case Command::kLogs:
            collectors.emplace_back(std::make_unique<LogCollector>());
            break;
        case Command::kCrash:
            collectors.emplace_back(std::make_unique<CrashCollector>());
            collectors.emplace_back(std::make_unique<PowerCollector>());
            break;
        case Command::kTopic: {
            const std::string topic = ToLower(context.sub_target);
            if (topic == "cpu" || topic == "memory" || topic == "gpu" || topic == "audio") {
                collectors.emplace_back(std::make_unique<SystemCollector>());
                collectors.emplace_back(std::make_unique<HardwareCollector>());
                collectors.emplace_back(std::make_unique<PowerCollector>());
            } else if (topic == "storage") {
                collectors.emplace_back(std::make_unique<StorageCollector>());
                collectors.emplace_back(std::make_unique<LogCollector>());
            } else if (topic == "power") {
                collectors.emplace_back(std::make_unique<PowerCollector>());
                collectors.emplace_back(std::make_unique<StorageCollector>());
            } else if (topic == "network" || topic == "drivers") {
                collectors.emplace_back(std::make_unique<DeviceCollector>());
                collectors.emplace_back(std::make_unique<LogCollector>());
            } else if (topic == "eventlog") {
                collectors.emplace_back(std::make_unique<LogCollector>());
            } else if (topic == "crash") {
                collectors.emplace_back(std::make_unique<CrashCollector>());
                collectors.emplace_back(std::make_unique<PowerCollector>());
            }
            break;
        }
        case Command::kHelp:
            break;
    }

    return collectors;
}
const char* SystemCollector::DisplayName() const { return "System Baseline"; }
const char* HardwareCollector::DisplayName() const { return "Hardware Inventory"; }
const char* StorageCollector::DisplayName() const { return "Storage Health"; }
const char* PowerCollector::DisplayName() const { return "Power/Thermal/Shutdown"; }
const char* CrashCollector::DisplayName() const { return "Crash/BSOD Metadata"; }
const char* DeviceCollector::DisplayName() const { return "Device Diagnostics"; }
const char* LogCollector::DisplayName() const { return "Event Logs"; }
