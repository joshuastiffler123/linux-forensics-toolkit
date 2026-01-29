# Function and Class Reference

Quick reference for all functions and classes in the Linux Forensics Toolkit.

---

## linux_analyzer.py

Main orchestrator that runs all forensic analyzers in parallel.

### Classes

| Class | Description |
|-------|-------------|
| `Style` | ANSI escape codes for colored console output. Provides color constants (RED, GREEN, etc.) and a method to enable Windows ANSI support. |

### Functions

| Function | Description |
|----------|-------------|
| `extract_hostname_from_tarball(tarball_path)` | Extracts the hostname from a UAC tarball by reading the `hostname` file inside. Falls back to parsing the tarball filename if the file is not found. |
| `extract_hostname_from_directory(dir_path)` | Extracts the hostname from an extracted UAC directory by reading the `hostname` file. Falls back to the directory name if not found. |
| `run_login_timeline(source_path, output_dir, hostname)` | Runs the login timeline analyzer on the source. Returns a dictionary with success status, event count, and output files. |
| `run_journal_analyzer(source_path, output_dir, hostname)` | Runs the journal analyzer on the source. Returns a dictionary with success status, event count, and output files. |
| `run_persistence_hunter(source_path, output_dir, hostname)` | Runs the persistence hunter on the source. Returns a dictionary with success status, finding count, and output files. |
| `run_security_analyzer(source_path, output_dir, hostname)` | Runs the security analyzer on the source. Returns a dictionary with success status, finding count, and output files. |
| `create_summary_report(output_dir, hostname, results, start_time, end_time)` | Creates a text summary report of all analyzer results. Writes statistics, findings summary, and file list to a summary file. |
| `run_analysis(source_path, output_base, parallel, verbose)` | Main orchestrator function that runs all analyzers. Handles parallel/sequential execution and creates the output directory structure. |
| `main()` | Entry point that parses command line arguments and calls run_analysis. |

---

## linux_login_timeline.py

Extracts and timelines Linux login/authentication events from system logs.

### Classes

| Class | Description |
|-------|-------------|
| `Style` | ANSI escape codes for colored console output. Same as in linux_analyzer.py. |
| `UACTarballHandler` | Handles reading files from UAC tarballs without full extraction. Provides methods to list files, get file contents, and find files matching patterns. |
| `TimelineEvent` | Dataclass representing a single timeline event with timestamp, event type, username, source IP, hostname, description, severity, source file, and raw data. |
| `LinuxLoginTimeline` | Main analyzer class that processes UAC tarballs or directories. Collects events from all log sources and exports to CSV. |

### Functions

| Function | Description |
|----------|-------------|
| `resolve_path(path)` | Resolves a path by expanding user home directory and converting to absolute path. Handles both Windows and Linux path formats. |
| `is_safe_path(base_path, target_path)` | Security check to prevent path traversal attacks. Ensures the target path stays within the base directory. |
| `safe_extract_member(tar, member, dest_dir)` | Safely extracts a tarball member with path traversal protection. Returns the extracted path or None if unsafe. |
| `open_file(filepath, binary, data)` | Opens a file with automatic gzip detection. If data is provided, wraps it in a file-like object instead of reading from disk. |
| `find_log_files(base_path, pattern)` | Finds log files matching a pattern, including rotated logs (.1, .2.gz, etc.). Uses glob with special character escaping. |
| `decode_string(data)` | Decodes bytes to string, trying multiple encodings (utf-8, latin-1, ascii). Falls back gracefully on encoding errors. |
| `is_valid_ip(ip_str)` | Validates an IP address string. Checks for valid IPv4 format and rejects common false positives like version numbers. |
| `extract_ip_from_message(message)` | Extracts IP address from a log message. Handles various formats like "from X", "rhost=X", and bracketed IPs. |
| `is_valid_username(username)` | Validates a username string. Rejects common false positives like command flags, system words, and invalid formats. |
| `sanitize_username(username)` | Cleans up a username by removing quotes, trailing punctuation, and validating format. Returns empty string if invalid. |
| `ip_from_int(addr)` | Converts an integer IP address to dotted-quad string format. Used when parsing binary log formats. |
| `parse_utmp_record(data)` | Parses a single utmp/wtmp/btmp record from binary data. Extracts user, terminal, host, timestamp, and login type. |
| `parse_utmp_file(filepath, log_type, data)` | Parses wtmp/btmp/utmp binary files. Returns list of TimelineEvents for logins, logouts, boots, and failed attempts. |
| `parse_lastlog(filepath, data, passwd_data)` | Parses the lastlog binary file to get last login times. Uses passwd to map UIDs to usernames. |
| `make_naive(dt)` | Removes timezone information from a datetime object. Used to ensure consistent timestamp handling. |
| `parse_syslog_timestamp(timestamp_str, reference_date)` | Parses syslog-style timestamps (e.g., "Jan 15 10:30:00"). Infers the year from reference date or file modification time. |
| `parse_iso_timestamp(timestamp_str)` | Parses ISO 8601 format timestamps. Handles various formats with or without timezone info. |
| `parse_audit_timestamp(line)` | Extracts timestamp from audit log lines. Parses the msg=audit(epoch:serial) format. |
| `parse_auth_log(filepath, data, reference_date)` | Parses auth.log/secure files for authentication events. Extracts SSH logins, sudo commands, user changes, and failures. |
| `parse_audit_log(filepath, data)` | Parses audit.log files for security events. Extracts user authentication, authorization, and session events. |
| `parse_syslog_messages(filepath, data, reference_date)` | Parses syslog/messages files for relevant events. Extracts boot events, service starts, and authentication-related messages. |
| `parse_bash_history(filepath, data, username, file_mtime)` | Parses bash history files. Handles both timestamped (#epoch) and non-timestamped entries. |
| `find_history_files_in_tarball(handler)` | Finds all bash/shell history files in a tarball. Returns list of (filepath, username, mtime) tuples. |
| `process_batch(input_dir, output_dir, recursive, verbose, summary)` | Batch processes multiple tarballs in a directory. Creates individual timeline CSVs for each. |
| `main()` | Entry point that parses arguments and runs single file or batch processing. |

---

## linux_journal_analyzer.py

Analyzes systemd journal binary logs.

### Classes

| Class | Description |
|-------|-------------|
| `Style` | ANSI escape codes for colored console output. Provides color formatting for terminal messages. |
| `JournalEntry` | Dataclass representing a journal entry with timestamp, hostname, unit, message, priority, category, PID, UID, and source file. |
| `UACHandler` | Handles reading files from UAC tarballs or directories. Provides unified interface for accessing files regardless of source type. |
| `JournalParser` | Parses systemd journal binary files. Handles the binary format and extracts fields like timestamp, message, unit, and priority. |
| `JournalAnalyzer` | Main analyzer class that processes all journal files in a source. Categorizes entries and filters security-relevant events. |

### Functions

| Function | Description |
|----------|-------------|
| `export_csv(entries, output_path, max_message_length)` | Exports journal entries to a CSV file. Optionally truncates long messages to specified length. |
| `export_security_report(entries, output_path, max_message_length)` | Exports only security-relevant journal entries to a separate CSV. Filters for auth, error, and suspicious events. |
| `main()` | Entry point that parses arguments, runs analysis, and exports results to CSV files. |

---

## linux_persistence_hunter.py

Detects persistence mechanisms with MITRE ATT&CK mapping.

### Classes

| Class | Description |
|-------|-------------|
| `Style` | ANSI escape codes for colored console output. Enables cross-platform colored terminal output. |
| `PersistenceFinding` | Dataclass representing a persistence finding with filepath, technique, MITRE ID, severity, description, indicator, line number, and hashes. |
| `UACHandler` | Handles reading files from UAC tarballs or directories. Provides methods to list directories, get files, and search for patterns. |
| `PersistenceHunter` | Main hunter class containing all detection methods. Runs checks for cron, systemd, SSH keys, backdoor users, shell profiles, and more. |

### Functions

| Function | Description |
|----------|-------------|
| `is_safe_path(base_path, target_path)` | Security check to prevent path traversal attacks. Validates that resolved path stays within base directory. |
| `safe_extract_member(tar, member, extract_path)` | Safely extracts tarball members with security checks. Prevents extraction of files with dangerous paths. |
| `calculate_hashes(data)` | Calculates MD5 and SHA256 hashes of file data. Returns tuple of (md5_hex, sha256_hex). |
| `main()` | Entry point that parses arguments, runs the hunter, and exports findings to CSV. |

---

## linux_security_analyzer.py

Combined binary analysis and security scanning.

### Classes

| Class | Description |
|-------|-------------|
| `Style` | ANSI escape codes for colored console output. Consistent with other scripts for terminal formatting. |
| `SecurityFinding` | Dataclass representing a security finding with filepath, finding type, severity, description, MITRE ID, indicator, hashes, and metadata. |
| `UACHandler` | Handles reading files from UAC tarballs or directories. Supports both compressed and uncompressed sources. |
| `LinuxSecurityAnalyzer` | Main analyzer class that scans for suspicious binaries, SUID files, rootkit traces, and persistence mechanisms. |

### Functions

| Function | Description |
|----------|-------------|
| `is_safe_path(base_path, target_path)` | Security check to prevent path traversal attacks. Used when extracting or accessing files. |
| `calculate_hashes(data)` | Calculates MD5 and SHA256 hashes of binary data. Used for IOC matching and file identification. |
| `is_elf_binary(data)` | Checks if file data starts with ELF magic bytes. Returns True for Linux executable binaries. |
| `is_script(data)` | Checks if file data starts with a shebang (#!). Returns True for shell scripts, Python scripts, etc. |
| `is_executable(data)` | Checks if file is executable (ELF binary or script). Combines is_elf_binary and is_script checks. |
| `is_hidden_path(path)` | Checks if a path contains hidden components (starting with dot). Used to flag suspicious hidden files. |
| `load_hash_list(filepath)` | Loads a list of known-bad hashes from a file. Supports MD5 and SHA256 formats for IOC matching. |
| `main()` | Entry point that parses arguments, runs analysis, and exports findings to CSV files. |

---

---

## linux_memory_analyzer.py

Volatility 3 automation for Linux memory forensics.

### Classes

| Class | Description |
|-------|-------------|
| `Style` | ANSI escape codes for colored console output. Consistent styling for terminal messages. |
| `VolatilityRunner` | Handles running Volatility 3 plugins against a memory image. Manages command execution, output capture, and error handling for each plugin. |
| `LinuxMemoryAnalyzer` | Main analyzer class that orchestrates memory analysis. Validates inputs, runs all plugins, and generates summary reports. |

### Functions

| Function | Description |
|----------|-------------|
| `quick_triage(image_path, vol_path, verbose)` | Runs a quick triage analysis with only essential plugins (pslist, netstat, bash, malfind). Returns results dictionary for rapid initial assessment. |
| `main()` | Entry point that parses command line arguments and runs either quick triage or full analysis based on flags. |

### Plugin Categories

The analyzer runs these Volatility 3 plugin categories:

| Category | Plugins |
|----------|---------|
| Kernel Identification | banners, linux.info |
| Process Analysis | linux.pslist, linux.psscan, linux.pstree, linux.psaux |
| Network Analysis | linux.netstat, linux.sockstat, linux.unix |
| Kernel Module Integrity | linux.lsmod, linux.check_modules, linux.hidden_modules |
| Memory Injection | linux.malfind, linux.proc.Maps |
| Privileges | linux.check_creds |
| Environment | linux.envars |
| User Activity | linux.who, linux.bash |

---

## Common Patterns

### Error Handling
All scripts use try/except blocks around file operations and parsing. Failed operations are logged but don't stop processing.

### Timestamp Handling
All timestamps are converted to UTC for forensic consistency. A secondary local time column is provided for reference.

### Path Security
All scripts validate paths to prevent directory traversal attacks when extracting or accessing files from tarballs.

### Output Format
All scripts output CSV files with consistent column naming. Severity levels are: CRITICAL, HIGH, MEDIUM, LOW, INFO.
