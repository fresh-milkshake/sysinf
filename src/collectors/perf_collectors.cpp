#include "collectors.h"

#include "collectors/common.h"

using collectors_internal::AddPartial;
using collectors_internal::AddProbe;
using collectors_internal::Meta;
using collectors_internal::Ps;

CollectorResult ThermalCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "thermal";
    Meta(c, &r);
    AddProbe(c, &r, "thermal.sensors", "Thermal sensor snapshot", "Thermal zone telemetry captured.", "wmi.thermalzone",
             Ps("Get-WmiObject -Namespace root/wmi -Class MSAcpi_ThermalZoneTemperature | Select-Object CurrentTemperature,InstanceName | Format-Table -AutoSize"), true, true, 20);
    AddPartial(c, &r);
    return r;
}

CollectorResult ProcessPressureCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "processes";
    Meta(c, &r);
    AddProbe(c, &r, "processes.top", "Top process pressure", "Top CPU/memory processes captured.", "ps.process_top",
             Ps("Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name,Id,CPU,WS,PM,StartTime | Format-Table -AutoSize"), false, false, 24);
    AddPartial(c, &r);
    return r;
}

CollectorResult SchedulerCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "scheduler";
    Meta(c, &r);
    AddProbe(c, &r, "scheduler.queue", "Processor queue length", "Scheduler queue counter sampled.", "perfcounter.scheduler_queue",
             Ps("Get-Counter '\\System\\Processor Queue Length' | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize"), true, false, 12);
    AddPartial(c, &r);
    return r;
}

CollectorResult MemoryPressureCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "memory_pressure";
    Meta(c, &r);
    AddProbe(c, &r, "memory.pressure", "Memory pressure signals", "Memory and paging metrics captured.", "cim.memory_os",
             Ps("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory,SizeStoredInPagingFiles,FreeSpaceInPagingFiles | Format-List"), false, false, 20);
    AddPartial(c, &r);
    return r;
}

CollectorResult IoLatencyCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "io_latency";
    Meta(c, &r);
    AddProbe(c, &r, "io.latency", "Disk IO latency counters", "Read/write latency counters captured.", "perfcounter.io_latency",
             Ps("Get-Counter '\\PhysicalDisk(_Total)\\Avg. Disk sec/Read','\\PhysicalDisk(_Total)\\Avg. Disk sec/Write' | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize"), true, false, 16);
    AddPartial(c, &r);
    return r;
}

CollectorResult DiskQueueCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "disk_queue";
    Meta(c, &r);
    AddProbe(c, &r, "disk.queue", "Disk queue length", "Disk queue counter sampled.", "perfcounter.disk_queue",
             Ps("Get-Counter '\\PhysicalDisk(_Total)\\Current Disk Queue Length' | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize"), true, false, 12);
    AddPartial(c, &r);
    return r;
}

CollectorResult GpuTelemetryCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "gpu_telemetry";
    Meta(c, &r);
    AddProbe(c, &r, "gpu.telemetry", "GPU utilization telemetry", "GPU engine utilization captured.", "perfcounter.gpu",
             Ps("Get-Counter '\\GPU Engine(*)\\Utilization Percentage' | Select-Object -ExpandProperty CounterSamples | Select-Object -First 20 Path,CookedValue | Format-Table -AutoSize"), true, false, 24);
    AddPartial(c, &r);
    return r;
}

CollectorResult PowerPolicyCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "power_policy";
    Meta(c, &r);
    AddProbe(c, &r, "powerpolicy.active", "Active power scheme", "Active Windows power scheme captured.", "powercfg.active_scheme", "powercfg /getactivescheme", false, false, 8);
    AddProbe(c, &r, "powerpolicy.details", "Power policy details", "Power policy details captured (truncated).", "powercfg.details", "powercfg /q", true, false, 24);
    AddPartial(c, &r);
    return r;
}

CollectorResult InterruptCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "interrupts";
    Meta(c, &r);
    AddProbe(c, &r, "interrupts.dpc", "Interrupt/DPC counters", "Interrupt and DPC time counters captured.", "perfcounter.interrupts",
             Ps("Get-Counter '\\Processor(_Total)\\% Interrupt Time','\\Processor(_Total)\\% DPC Time' | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize"), true, false, 16);
    AddPartial(c, &r);
    return r;
}

CollectorResult StartupImpactCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "startup_impact";
    Meta(c, &r);
    AddProbe(c, &r, "startup.commands", "Startup commands", "Startup command list captured.", "cim.startup_command",
             Ps("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | Format-Table -AutoSize"), false, false, 22, "startup");
    AddProbe(c, &r, "startup.tasks", "Scheduled tasks surface", "Scheduled task startup surface captured.", "tasks.startup",
             Ps("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object -First 30 TaskName,TaskPath,State | Format-Table -AutoSize"), true, false, 22, "scheduledtasks");
    AddPartial(c, &r);
    return r;
}

CollectorResult ServicesHealthCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "services_health";
    Meta(c, &r);
    AddProbe(c, &r, "services.health", "Auto-start services not running", "Service health sample captured.", "services.auto_nonrunning",
             Ps("Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object -First 40 Name,DisplayName,Status,StartType | Format-Table -AutoSize"), false, false, 24);
    AddPartial(c, &r);
    return r;
}

CollectorResult RealtimeAudioCollector::Collect(Context& c) const {
    CollectorResult r;
    r.collector_id = "realtime_audio";
    Meta(c, &r);
    AddProbe(c, &r, "audio.devices", "Audio device status", "Audio device status captured.", "cim.audio_devices",
             Ps("Get-CimInstance Win32_SoundDevice | Select-Object Name,Status,Manufacturer,PNPDeviceID | Format-Table -AutoSize"), false, false, 20);
    AddProbe(c, &r, "audio.dpc", "Realtime audio DPC signal", "DPC counter sampled for realtime audio diagnostics.", "perfcounter.audio_dpc",
             Ps("Get-Counter '\\Processor(_Total)\\% DPC Time' | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | Format-Table -AutoSize"), true, false, 10);
    AddPartial(c, &r);
    return r;
}

const char* ThermalCollector::DisplayName() const { return "Thermal"; }
const char* ProcessPressureCollector::DisplayName() const { return "Processes"; }
const char* SchedulerCollector::DisplayName() const { return "Scheduler"; }
const char* MemoryPressureCollector::DisplayName() const { return "Memory Pressure"; }
const char* IoLatencyCollector::DisplayName() const { return "IO Latency"; }
const char* DiskQueueCollector::DisplayName() const { return "Disk Queue"; }
const char* GpuTelemetryCollector::DisplayName() const { return "GPU Telemetry"; }
const char* PowerPolicyCollector::DisplayName() const { return "Power Policy"; }
const char* InterruptCollector::DisplayName() const { return "Interrupts"; }
const char* StartupImpactCollector::DisplayName() const { return "Startup Impact"; }
const char* ServicesHealthCollector::DisplayName() const { return "Services Health"; }
const char* RealtimeAudioCollector::DisplayName() const { return "Realtime Audio"; }
