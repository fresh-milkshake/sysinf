# sysinf

```
sysinf.exe - Windows Incident Diagnostics CLI (targeted mode)
Focused diagnostics for explicit topics and filters.

USAGE
  sysinf <subcommand> [options]

SUBCOMMANDS
  summary   Essential baseline overview (system, hardware, storage, power, services-health)
  incident  Preset-focused diagnostics
  hardware  Device and driver-oriented diagnostics
  logs      Event log diagnostics (System/Application)
  crash     Crash/BSOD metadata diagnostics
  topic     Primary command for targeted topic collection

GLOBAL OPTIONS
  --verbosity <0..5>         Default: 1
  --format <pretty|tagged>   Default: pretty
  --token-mode <normal|economy>  Default: normal
  --level <quick|normal|deep>    Default: normal
  --include <csv>            Include facets inside selected topics
  --exclude <csv>            Exclude facets inside selected topics
  --sources <csv>            Force data sources (can enable heavy probes)
  --since <duration|datetime> Default: 24h (examples: 6h, 2d, 2026-03-01T00:00:00)
  --max-events <N>           Default: 100
  --no-color                 Disable ANSI coloring in pretty mode

INCIDENT PRESETS
  sound, shutdown, crash, device

TOPIC TARGETS
  cpu, memory, storage, gpu, audio, power, network, drivers, eventlog, crash
  thermal, processes, scheduler, memory-pressure, io-latency, disk-queue, gpu-telemetry
  power-policy, interrupts, startup-impact, services-health, realtime-audio

EXAMPLES
  sysinf summary --level quick
  sysinf topic --target thermal,io-latency --include sensors,queue --since 2h
  sysinf topic --target gpu-telemetry --level deep --sources perfcounter,wmi
  sysinf topic --target startup-impact --exclude scheduledtasks --format tagged

EXIT CODES
  0  Successful run with no warning/critical/error findings
  1  Any warning/critical/error finding OR runtime collection problem
```