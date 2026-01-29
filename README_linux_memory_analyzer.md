# Linux Memory Analyzer

Volatility 3 automation for Linux memory forensics.

## Overview

`linux_memory_analyzer.py` automates running Volatility 3 plugins against Linux memory dumps and outputs results in CSV format. It provides organized analysis across multiple categories with progress tracking and error handling.

## Requirements

- **Python 3.6+**
- **Volatility 3** installed and accessible in PATH
  ```bash
  pip install volatility3
  ```

## Supported Memory Formats

- AVML dumps (`.lime`)
- LiME dumps (`.lime`, `.mem`)
- Raw memory dumps (`.raw`, `.mem`)
- ELF core dumps

## Usage

### Full Analysis

```bash
# Run all standard plugins
python linux_memory_analyzer.py -i memory.lime

# Include optional plugins (rootkit detection, file analysis)
python linux_memory_analyzer.py -i memory.lime --all

# Specify output directory
python linux_memory_analyzer.py -i memory.lime -o ./results/
```

### Quick Triage

```bash
# Run only essential plugins for rapid triage
python linux_memory_analyzer.py -i memory.lime --quick
```

Quick triage runs: `linux.info`, `linux.pslist`, `linux.netstat`, `linux.bash`, `linux.malfind`

### Specify Volatility Path

```bash
# If vol/vol.py isn't in PATH
python linux_memory_analyzer.py -i memory.lime --vol-path /opt/volatility3/vol.py
```

## Analysis Categories

### Standard Plugins (always run)

| Category | Plugins | Description |
|----------|---------|-------------|
| **Kernel Identification** | `banners`, `linux.info` | Kernel version, system information |
| **Process Analysis** | `linux.pslist`, `linux.psscan`, `linux.pstree`, `linux.psaux` | Running processes, hidden processes, process tree |
| **Network Analysis** | `linux.netstat`, `linux.sockstat`, `linux.unix` | Network connections, sockets |
| **Kernel Modules** | `linux.lsmod`, `linux.check_modules`, `linux.hidden_modules` | Loaded modules, rootkit detection |
| **Memory Injection** | `linux.malfind`, `linux.proc.Maps` | Malicious code injection |
| **Privileges** | `linux.check_creds` | Credential anomalies |
| **Environment** | `linux.envars` | Process environment variables |
| **User Activity** | `linux.who`, `linux.bash` | Logged users, bash history |

### Optional Plugins (with `--all`)

| Category | Plugins | Description |
|----------|---------|-------------|
| **File Analysis** | `linux.lsof`, `linux.find_file` | Open files |
| **Rootkit Detection** | `linux.check_syscall`, `linux.check_idt`, `linux.tty_check` | Syscall/IDT hooks |
| **Advanced** | `linux.kmsg`, `linux.mountinfo`, `linux.library_list` | Kernel messages, mounts, libraries |

## Output

Creates a directory `[image_name]_memory_analysis/` containing:

```
memory_analysis/
├── banners.csv              # Kernel identification
├── linux_info.csv           # System information
├── pslist.csv               # Process list
├── psscan.csv               # Process scan
├── pstree.csv               # Process tree
├── psaux.csv                # Processes with arguments
├── netstat.csv              # Network connections
├── sockstat.csv             # Socket statistics
├── unix_sockets.csv         # Unix sockets
├── lsmod.csv                # Loaded kernel modules
├── check_modules.csv        # Module integrity check
├── hidden_modules.csv       # Hidden module detection
├── malfind.csv              # Malicious memory regions
├── proc_maps.csv            # Process memory maps
├── check_creds.csv          # Credential check
├── envars.csv               # Environment variables
├── who.csv                  # Logged in users
├── bash_history.csv         # Bash command history
├── analysis_summary.txt     # Summary report
└── *.stderr                 # Error logs per plugin
```

## Integration with Toolkit

This analyzer handles **memory dumps**, while the other tools handle **disk artifacts**:

| Tool | Input | Analysis Type |
|------|-------|---------------|
| `linux_analyzer.py` | UAC tarball / directory | Disk forensics (logs, configs) |
| `linux_memory_analyzer.py` | Memory dump (.lime, .raw) | Memory forensics (processes, network, etc.) |

### Combined Workflow

```bash
# 1. Analyze disk artifacts from UAC collection
python linux_analyzer.py -s hostname-uac.tar.gz

# 2. Analyze memory dump if available
python linux_memory_analyzer.py -i hostname-avml.lime

# Results will be in separate directories for correlation
```

## Command Line Options

```
usage: linux_memory_analyzer.py [-h] -i IMAGE [-o OUTPUT] [--vol-path VOL_PATH]
                                [--quick] [--all] [-q] [-v]

options:
  -h, --help            show this help message and exit
  -i IMAGE, --image IMAGE
                        Path to Linux memory image
  -o OUTPUT, --output OUTPUT
                        Output directory
  --vol-path VOL_PATH   Path to Volatility 3 executable
  --quick               Quick triage mode (essential plugins only)
  --all                 Include optional plugins
  -q, --quiet           Suppress progress output
  -v, --version         show version
```

## Example Output

```
============================================================
  Linux Memory Analyzer v1.0.0
============================================================

Image: /evidence/server01-avml.lime
Output: /evidence/server01-avml_memory_analysis
Image Size: 8192.0 MB

[Kernel Identification]
  Running banners... OK (1 rows)
  Running linux.info... OK (15 rows)

[Process Analysis]
  Running linux.pslist... OK (127 rows)
  Running linux.psscan... OK (142 rows)
  Running linux.pstree... OK (127 rows)
  Running linux.psaux... OK (127 rows)

[Network Analysis]
  Running linux.netstat... OK (23 rows)
  Running linux.sockstat... OK (45 rows)
  Running linux.unix... OK (18 rows)

...

============================================================
  Analysis Complete
============================================================

Duration: 245.3 seconds
Successful: 17 plugins
Failed: 1 plugins

Output Directory: /evidence/server01-avml_memory_analysis
Summary: /evidence/server01-avml_memory_analysis/analysis_summary.txt
```

## Troubleshooting

### Volatility Not Found

```bash
# Install Volatility 3
pip install volatility3

# Or specify path manually
python linux_memory_analyzer.py -i image.lime --vol-path /path/to/vol.py
```

### Plugin Failures

Check the `.stderr` files in the output directory for detailed error messages. Common issues:
- Missing symbol tables for the kernel version
- Unsupported memory format
- Corrupted memory dump

### Symbol Tables

Volatility 3 needs symbol tables for the target kernel. Download from:
https://github.com/volatilityfoundation/volatility3#symbol-tables

## License

MIT License
