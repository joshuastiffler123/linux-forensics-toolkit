#!/usr/bin/env python3
"""
Linux Persistence Hunter - PANIX-Style Persistence Detection Tool

This script detects Linux persistence mechanisms commonly used by attackers,
including all techniques implemented by PANIX (https://github.com/Aegrah/PANIX)
and documented in the Elastic Security Labs Linux Detection Engineering series.

Detects:
- Scheduled Tasks (cron, at jobs, systemd timers)
- SSH Authorized Keys modifications
- Backdoor users (UID=0, system user modifications)
- Init persistence (init.d, rc.local, systemd services, generators)
- Shell profile backdoors (.bashrc, .profile, etc.)
- LD_PRELOAD/LD_LIBRARY_PATH hijacking
- PAM backdoors
- Sudoers modifications
- SUID/Capabilities backdoors
- Udev rules persistence
- XDG Autostart entries
- Git hooks/pagers
- MOTD backdoors
- Polkit rules
- Package manager hooks
- Web shells
- Kernel modules (LKM rootkits)
- Container escape configurations
- Message queue persistence
- Bind/Reverse shells
- Systemd socket activation

Extended Checks (NEW):
- SSHD config analysis (PermitRootLogin, AuthorizedKeysFile, etc.)
- Environment persistence (/etc/environment, pam_env.conf, pam_env.d)
- Docker persistence (bind mounts, privileged containers)
- Kernel module configs (modprobe.d, modules-load.d)
- Dracut modules (initramfs persistence)
- Sketchy code patterns (curl, wget, nc, bash -i, /dev/tcp)
- NPM package backdoors (postinstall hooks)
- Python backdoors (setup.py, sitecustomize.py)
- Makefile backdoors (curl/wget/bash in make recipes)
- IP connection patterns (hardcoded IP:port)
- Active git hooks (non-sample hooks)

Author: Security Tools
Version: 1.1.0
License: MIT

Requirements: Python 3.6+ (standard library only)

References:
- PANIX: https://github.com/Aegrah/PANIX
- MITRE ATT&CK: https://attack.mitre.org/
- Elastic Security Labs - Linux Detection Engineering:
  - Primer: https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
  - Sequel: https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms
  - Continuation: https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms
  - Approaching Summit: https://www.elastic.co/security-labs/approaching-the-summit-on-persistence
  - Grand Finale: https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence
"""

import argparse
import csv
import gzip
import hashlib
import io
import os
import re
import stat
import struct
import sys
import tarfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union

__version__ = "1.1.0"


# ============================================================================
# Console Styling
# ============================================================================

class Style:
    """ANSI escape codes for console styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    
    ERROR = RED
    SUCCESS = GREEN
    WARNING = YELLOW
    INFO = CYAN
    HEADER = MAGENTA
    CRITICAL = f"{RED}{BOLD}"
    
    @staticmethod
    def enable_windows_ansi():
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class PersistenceFinding:
    """Represents a persistence mechanism finding."""
    filepath: str
    technique: str
    technique_id: str  # MITRE ATT&CK ID
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    indicator: str = ""  # The specific IOC found
    line_number: int = 0
    raw_content: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    file_mode: str = ""
    extra_info: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "Filepath": self.filepath,
            "Technique": self.technique,
            "MITRE_ATT&CK_ID": self.technique_id,
            "Severity": self.severity,
            "Description": self.description,
            "Indicator": self.indicator[:500] if self.indicator else "",
            "Line_Number": self.line_number,
            "Raw_Content": self.raw_content[:1000] if self.raw_content else "",
            "MD5": self.hash_md5,
            "SHA256": self.hash_sha256,
            "File_Mode": self.file_mode,
            "Extra_Info": str(self.extra_info) if self.extra_info else ""
        }


# ============================================================================
# MITRE ATT&CK Mappings (from PANIX)
# ============================================================================

MITRE_MAPPINGS = {
    # Scheduled Tasks (T1053)
    "at_job": ("Scheduled Task/Job: At", "T1053.002"),
    "cron": ("Scheduled Task/Job: Cron", "T1053.003"),
    "timer": ("Scheduled Task/Job: Systemd Timers", "T1053.006"),
    
    # Account Manipulation (T1098)
    "authorized_keys": ("Account Manipulation: SSH Authorized Keys", "T1098.004"),
    "ssh_key": ("Account Manipulation: SSH Authorized Keys", "T1098.004"),
    "passwd": ("Account Manipulation", "T1098"),
    "shadow": ("Account Manipulation: Password Hash", "T1098"),
    
    # Create Account (T1136)
    "backdoor_user": ("Create Account: Local Account", "T1136.001"),
    
    # Boot/Logon Initialization (T1037)
    "initd": ("Boot or Logon Initialization Scripts", "T1037"),
    "rc_local": ("Boot or Logon Initialization Scripts: RC Scripts", "T1037.004"),
    "motd": ("Boot or Logon Initialization Scripts", "T1037"),
    
    # Boot/Logon Autostart (T1547)
    "lkm": ("Boot or Logon Autostart Execution: Kernel Modules", "T1547.006"),
    "xdg": ("Boot or Logon Autostart Execution: XDG Autostart", "T1547.013"),
    
    # Pre-OS Boot (T1542)
    "grub": ("Pre-OS Boot", "T1542"),
    "initramfs": ("Pre-OS Boot", "T1542"),
    
    # Create/Modify System Process (T1543)
    "systemd": ("Create or Modify System Process: Systemd Service", "T1543.002"),
    "generator": ("Create or Modify System Process: Systemd Service", "T1543.002"),
    "dbus": ("Create or Modify System Process", "T1543"),
    "socket_activation": ("Create or Modify System Process: Systemd Service", "T1543.002"),
    
    # Abuse Elevation Control (T1548)
    "suid": ("Abuse Elevation Control Mechanism: Setuid/Setgid", "T1548.001"),
    "sudoers": ("Abuse Elevation Control Mechanism: Sudo", "T1548.003"),
    "capabilities": ("Abuse Elevation Control Mechanism", "T1548"),
    
    # Modify Authentication (T1556)
    "pam": ("Modify Authentication Process: PAM", "T1556.003"),
    "polkit": ("Modify Authentication Process", "T1556"),
    
    # Event Triggered Execution (T1546)
    "shell_profile": ("Event Triggered Execution: Unix Shell Configuration", "T1546.004"),
    "git_hook": ("Event Triggered Execution", "T1546"),
    "udev": ("Event Triggered Execution: Udev Rules", "T1546.017"),
    "network_manager": ("Event Triggered Execution", "T1546"),
    "package_manager": ("Event Triggered Execution: Installer Packages", "T1546.016"),
    "malicious_package": ("Event Triggered Execution: Installer Packages", "T1546.016"),
    "trap": ("Event Triggered Execution: Trap", "T1546.005"),
    
    # Hijack Execution Flow (T1574)
    "ld_preload": ("Hijack Execution Flow: Dynamic Linker Hijacking", "T1574.006"),
    "path_interception": ("Hijack Execution Flow: Path Interception", "T1574.007"),
    
    # Command and Scripting (T1059)
    "bind_shell": ("Command and Scripting Interpreter: Unix Shell", "T1059.004"),
    "reverse_shell": ("Command and Scripting Interpreter: Unix Shell", "T1059.004"),
    
    # Server Software Component (T1505)
    "web_shell": ("Server Software Component: Web Shell", "T1505.003"),
    
    # Other
    "rootkit": ("Rootkit", "T1014"),
    "system_binary": ("Compromise Host Software Binary", "T1554"),
    "malicious_container": ("Escape to Host", "T1610"),
    "message_queue": ("Inter-Process Communication", "T1559"),
    
    # New checks
    "sshd_config": ("Remote Services: SSH", "T1021.004"),
    "environment_persistence": ("Event Triggered Execution: Unix Shell Configuration", "T1546.004"),
    "docker_persistence": ("Container Administration Command", "T1609"),
    "modprobe": ("Boot or Logon Autostart Execution: Kernel Modules", "T1547.006"),
    "dracut": ("Pre-OS Boot", "T1542"),
    "sketchy_code": ("Command and Scripting Interpreter", "T1059"),
    "npm_backdoor": ("Supply Chain Compromise: Compromise Software Dependencies", "T1195.001"),
    "python_backdoor": ("Supply Chain Compromise: Compromise Software Dependencies", "T1195.001"),
    "makefile_backdoor": ("Supply Chain Compromise", "T1195"),
    "ip_connection": ("Network Service Discovery", "T1046"),
    "git_hook_active": ("Event Triggered Execution", "T1546"),
}


# ============================================================================
# Detection Patterns
# ============================================================================

# Suspicious patterns in shell scripts/configs
# Based on Elastic Security Labs Linux Detection Engineering series
SHELL_BACKDOOR_PATTERNS = [
    # Reverse shells - comprehensive list from Elastic research
    (r'bash\s+-i\s+>&\s*/dev/tcp/', "Bash /dev/tcp reverse shell"),
    (r'bash\s+-c.*>/dev/tcp/', "Bash -c /dev/tcp shell"),
    (r'sh\s+-i\s+>&\s*/dev/(tcp|udp)/', "Shell /dev/tcp redirect"),
    (r'exec\s+\d+<>/dev/tcp/', "Bash exec TCP redirect"),
    (r'0<&\d+-\s*;exec\s+\d+<>/dev/tcp/', "Bash interactive TCP shell"),
    
    # Netcat variants
    (r'nc\s+.*-e\s+/bin/(ba)?sh', "Netcat -e reverse shell"),
    (r'nc\s+.*-c\s+/bin/(ba)?sh', "Netcat -c reverse shell"),
    (r'ncat\s+.*-e\s+/bin/(ba)?sh', "Ncat reverse shell"),
    (r'nc\.traditional.*-e', "Netcat traditional -e shell"),
    (r'nc\.openbsd.*\|.*sh', "Netcat openbsd pipe shell"),
    (r'mkfifo\s+/tmp/.*nc\s+', "Named pipe netcat shell"),
    (r'rm\s+/tmp/f;mkfifo\s+/tmp/f', "Mkfifo netcat pattern"),
    
    # Socat
    (r'socat.*EXEC:', "Socat EXEC shell"),
    (r'socat.*TCP:.*EXEC', "Socat TCP EXEC"),
    (r'socat.*pty.*EXEC', "Socat PTY shell"),
    
    # Python reverse shells
    (r'python.*socket.*connect.*subprocess', "Python socket subprocess"),
    (r'python.*-c.*import\s+socket', "Python socket import"),
    (r"python.*socket\.socket\(.*\.connect\(", "Python socket connect"),
    (r'python.*pty\.spawn', "Python PTY spawn"),
    (r'python.*os\.dup2.*socket', "Python os.dup2 shell"),
    
    # Perl reverse shells
    (r'perl.*socket.*exec', "Perl socket exec"),
    (r'perl.*-e.*socket\s*\(', "Perl -e socket"),
    (r'perl.*IO::Socket::INET', "Perl IO::Socket shell"),
    
    # Ruby reverse shells
    (r'ruby.*TCPSocket.*exec', "Ruby TCPSocket shell"),
    (r'ruby.*-rsocket.*spawn', "Ruby socket spawn"),
    
    # PHP reverse shells
    (r'php.*fsockopen.*exec', "PHP fsockopen shell"),
    (r'php.*\$sock\s*=\s*fsockopen', "PHP socket shell"),
    (r'php.*proc_open.*array', "PHP proc_open shell"),
    (r'php.*shell_exec.*\$_(GET|POST)', "PHP shell_exec injection"),
    
    # Other interpreters
    (r'lua.*socket\.connect', "Lua socket shell"),
    (r'awk.*\|getline', "AWK getline shell"),
    (r'openssl.*s_client.*\|.*sh', "OpenSSL reverse shell"),
    (r'telnet.*\|.*sh', "Telnet pipe shell"),
    
    # Bind shells (Elastic: T1059.004 bind shells)
    (r'nc\s+-l.*-p\s+\d+.*-e\s+/bin/', "Netcat bind shell"),
    (r'ncat\s+-l.*-e\s+/bin/', "Ncat bind shell"),
    (r'nc\s+-lvnp\s+\d+\s+-e', "Netcat verbose bind shell"),
    (r'socat.*TCP-LISTEN:.*EXEC', "Socat TCP-LISTEN bind"),
    (r'python.*socket.*bind.*listen', "Python bind shell"),
    
    # Encoded/obfuscated commands
    (r'base64\s+-d.*\|\s*(bash|sh)', "Base64 decoded execution"),
    (r'echo.*\|\s*base64\s+-d\s*\|\s*(bash|sh)', "Base64 pipe execution"),
    (r'eval\s*\$\(.*base64', "Eval base64 execution"),
    (r'python.*exec\(.*decode\(', "Python encoded exec"),
    (r'\$\(\s*echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64', "Inline base64 decode"),
    (r'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d', "Long base64 decode"),
    (r'xxd\s+-r\s+-p.*\|\s*(bash|sh)', "XXD hex decode to shell"),
    (r'printf.*\\x[0-9a-f].*\|\s*(bash|sh)', "Printf hex to shell"),
    
    # Remote script execution (Elastic: setsid/nohup patterns)
    (r'curl\s+.*\|\s*(bash|sh|python|perl)', "Curl pipe to shell"),
    (r'wget\s+.*-O\s*-\s*\|\s*(bash|sh)', "Wget pipe to shell"),
    (r'wget\s+.*-q.*-O\s*-\s*\|', "Wget quiet pipe"),
    (r'curl\s+.*-o\s*/tmp/.*&&.*sh\s+/tmp/', "Curl download and execute"),
    (r'curl\s+-s\s+.*\|', "Curl silent pipe"),
    (r'setsid\s+.*nohup', "Setsid nohup (background persistence)"),
    (r'nohup\s+.*&\s*$', "Nohup background execution"),
    (r'disown\s+-a.*&', "Disown background process"),
    
    # Persistence commands
    (r'crontab\s+-', "Crontab modification"),
    (r'chmod\s+[ugo]*\+s\s+', "SUID bit setting"),
    (r'chmod\s+4[0-7]{3}\s+', "SUID numeric mode"),
    (r'chmod\s+2[0-7]{3}\s+', "SGID numeric mode"),
    (r'setcap\s+', "Capability setting"),
    (r'chattr\s+\+i\s+', "Immutable attribute setting"),
    (r'chattr\s+\+a\s+', "Append-only attribute"),
    
    # Suspicious environment (Elastic: LD_PRELOAD hijacking)
    (r'export\s+LD_PRELOAD=', "LD_PRELOAD export"),
    (r'LD_PRELOAD=\S+\s+\S+', "LD_PRELOAD inline"),
    (r'export\s+LD_LIBRARY_PATH=.*(/tmp|/var/tmp|/dev/shm)', "Suspicious LD_LIBRARY_PATH"),
    (r'export\s+LD_AUDIT=', "LD_AUDIT export (library auditing)"),
    (r'export\s+PATH=.*(/tmp|/var/tmp|/dev/shm)', "Suspicious PATH modification"),
    
    # Meterpreter patterns
    (r'msfvenom', "Msfvenom payload generation"),
    (r'meterpreter', "Meterpreter reference"),
    (r'metasploit', "Metasploit reference"),
]

# Suspicious cron patterns (Elastic: T1053.003)
CRON_SUSPICIOUS_PATTERNS = [
    (r'\|\s*(bash|sh|python|perl)\s*$', "Pipe to shell in cron"),
    (r'/tmp/[^\s]+', "Execution from /tmp"),
    (r'/var/tmp/[^\s]+', "Execution from /var/tmp"),
    (r'/dev/shm/[^\s]+', "Execution from /dev/shm"),
    (r'/run/[^\s]+', "Execution from /run"),
    (r'curl\s+.*\|', "Curl pipe in cron"),
    (r'wget\s+.*\|', "Wget pipe in cron"),
    (r'base64.*\|', "Base64 in cron"),
    (r'\.hidden', "Hidden file in cron"),
    (r'/\.[^/]+/', "Hidden directory in cron"),
    (r'>\s*/dev/null\s+2>&1', "Output suppression in cron"),
    (r'@reboot', "@reboot cron (runs on boot)"),
    (r'\*\s+\*\s+\*\s+\*\s+\*', "Every minute cron (high frequency)"),
    (r'/dev/tcp/', "/dev/tcp in cron"),
    (r'nc\s+-', "Netcat in cron"),
    (r'ncat\s+', "Ncat in cron"),
]

# Systemd suspicious patterns (Elastic: T1543.002)
SYSTEMD_SUSPICIOUS_PATTERNS = [
    (r'ExecStart=.*/tmp/', "ExecStart from /tmp"),
    (r'ExecStart=.*/var/tmp/', "ExecStart from /var/tmp"),
    (r'ExecStart=.*/dev/shm/', "ExecStart from /dev/shm"),
    (r'ExecStart=.*/home/.*\.', "ExecStart from hidden home file"),
    (r'ExecStartPre=.*/bin/(ba)?sh', "ExecStartPre shell execution"),
    (r'ExecStartPost=.*/bin/(ba)?sh', "ExecStartPost shell execution"),
    (r'ExecStart=.*curl.*\|', "ExecStart curl pipe"),
    (r'ExecStart=.*wget.*\|', "ExecStart wget pipe"),
    (r'ExecStart=.*nc\s+-', "ExecStart netcat"),
    (r'ExecStart=.*python.*-c', "ExecStart python -c"),
    (r'ExecStart=.*base64', "ExecStart base64"),
    (r'Restart=always', "Restart=always (persistence)"),
    (r'WantedBy=multi-user\.target', "WantedBy multi-user (auto-start)"),
]

# Known rootkit indicators (Elastic: T1014, T1547.006)
ROOTKIT_INDICATORS = {
    # LKM Rootkits
    "diamorphine": ["diamorphine", "hide_module", "hide_file", "diamorphine.ko"],
    "reptile": ["reptile", "khook", "hide_port", "reptile.ko", "reptile_cmd"],
    "jynx": ["jynx", "ld_poison", "jynx2"],
    "azazel": ["azazel", "crypthook", "azazel.so"],
    "vlany": ["vlany", "libvlany", "vlany.so"],
    "bdvl": ["bdvl", "bedevil", "bdvl.so"],
    "beurk": ["beurk", "libselinux.so.1"],
    "brootus": ["brootus", "brootus.ko"],
    "suterusu": ["suterusu", "suterusu.ko"],
    "adore-ng": ["adore-ng", "adore", "adore.ko"],
    "phalanx": ["phalanx", "phalanx2"],
    "rkh": ["rkh", "rkhunter_hide"],
    "enyelkm": ["enyelkm", "enyelkm.ko"],
    "knark": ["knark", "knark.ko"],
    "modhide": ["modhide", "modhide.ko"],
    "override": ["override.ko"],
    # Userland rootkits
    "jynx_kit": ["jynx_kit", "bc.so"],
    "libprocesshider": ["libprocesshider", "processhider"],
    "xhide": ["xhide", "x-hide"],
    "unhide": ["unhide_rb", "unhide.rb"],
}

# Hidden/suspicious file patterns
HIDDEN_FILE_PATTERNS = [
    r'/\.[^/]+$',  # Hidden files
    r'/\.\s+',  # Space after dot
    r'/\.\./',  # Double dot directories (traversal)
    r'/\s+/',  # Space in path
    r'/ $',  # Trailing space
]

# Systemd generator paths (Elastic: T1543.002)
GENERATOR_PATHS = [
    "etc/systemd/system-generators/",
    "usr/lib/systemd/system-generators/",
    "lib/systemd/system-generators/",
    "run/systemd/system-generators/",
    "etc/systemd/user-generators/",
    "usr/lib/systemd/user-generators/",
]

# Socket activation paths
SOCKET_PATHS = [
    "etc/systemd/system/",
    "usr/lib/systemd/system/",
    "lib/systemd/system/",
]

# Web shell patterns
WEB_SHELL_PATTERNS = [
    (r'<\?php.*\$_(GET|POST|REQUEST)\s*\[.*\]\s*\(', "PHP shell via GET/POST"),
    (r'eval\s*\(\s*\$_(GET|POST|REQUEST)', "PHP eval shell"),
    (r'assert\s*\(\s*\$_(GET|POST|REQUEST)', "PHP assert shell"),
    (r'system\s*\(\s*\$_(GET|POST|REQUEST)', "PHP system shell"),
    (r'exec\s*\(\s*\$_(GET|POST|REQUEST)', "PHP exec shell"),
    (r'passthru\s*\(\s*\$_(GET|POST|REQUEST)', "PHP passthru shell"),
    (r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)', "PHP shell_exec"),
    (r'preg_replace.*\/e.*\$_', "PHP preg_replace shell"),
    (r'create_function.*\$_', "PHP create_function shell"),
    (r'call_user_func.*\$_', "PHP call_user_func shell"),
    (r'base64_decode\s*\(\s*\$_(GET|POST)', "PHP base64 shell"),
    (r'<%.*Runtime\.getRuntime\(\)\.exec', "JSP shell"),
    (r'ProcessBuilder.*getInputStream', "JSP ProcessBuilder shell"),
    (r'os\.system\s*\(.*request\.(GET|POST)', "Python web shell"),
    (r'subprocess.*request\.(GET|POST)', "Python subprocess shell"),
]

# PAM backdoor indicators
PAM_BACKDOOR_PATTERNS = [
    (r'pam_permit\.so', "pam_permit.so (allows any auth)"),
    (r'password\s+requisite\s+pam_permit\.so', "PAM password bypass"),
    (r'auth\s+sufficient\s+pam_permit\.so', "PAM auth bypass"),
    (r'auth\s+optional\s+pam_exec\.so', "PAM exec hook"),
    (r'session\s+optional\s+pam_exec\.so', "PAM session exec hook"),
]

# Sudoers backdoor patterns
SUDOERS_BACKDOOR_PATTERNS = [
    (r'ALL\s*=\s*\(ALL(:ALL)?\)\s*NOPASSWD:\s*ALL', "Full NOPASSWD sudo"),
    (r'NOPASSWD:\s*/bin/(bash|sh|zsh)', "NOPASSWD shell access"),
    (r'NOPASSWD:\s*/usr/bin/(python|perl|ruby)', "NOPASSWD interpreter"),
    (r'!authenticate', "Sudo no authentication"),
    (r'!requiretty', "Sudo no tty required"),
]

# ============================================================================
# NEW: Sketchy Code Detection Patterns
# ============================================================================

# Network/download/exec patterns - for scanning arbitrary code files
SKETCHY_CODE_PATTERNS = [
    # Network tools
    (r'\bcurl\b.*\|', "Curl piped to another command"),
    (r'\bwget\b.*\|', "Wget piped to another command"),
    (r'\bcurl\b.*-[sS]', "Curl silent mode"),
    (r'\bwget\b.*-q', "Wget quiet mode"),
    (r'\bnc\s+-', "Netcat with flags"),
    (r'\bncat\b', "Ncat usage"),
    (r'\bsocat\b', "Socat usage"),
    
    # Shell invocations
    (r'bash\s+-i', "Bash interactive mode"),
    (r'bash\s+-c\s+["\']', "Bash -c execution"),
    (r'/dev/tcp/', "/dev/tcp network redirection"),
    (r'/dev/udp/', "/dev/udp network redirection"),
    (r'exec\s+\d+<>/dev/tcp', "Bash TCP exec redirection"),
    
    # Socket/connection patterns
    (r'\bsocket\.connect\b', "Socket connect call"),
    (r'\bsocket\.socket\b', "Socket creation"),
    (r'\.connect\s*\(\s*\(', "Connect method call"),
    
    # HTTP methods in scripts
    (r'\bfetch\s*\(', "Fetch API call"),
    (r'\.post\s*\(', "HTTP POST method"),
    (r'requests\.(get|post|put)', "Python requests library"),
    (r'urllib\.request', "Python urllib request"),
    
    # Obfuscation
    (r'\bbase64\b', "Base64 encoding/decoding"),
    (r'\beval\b\s*\(', "Eval function call"),
    (r'\bobfusc', "Obfuscation reference"),
    (r'\.decode\s*\(', "Decode method call"),
    (r'\bexec\s*\(', "Exec function call"),
]

# Persistence-related patterns in code
PERSISTENCE_CODE_PATTERNS = [
    (r'\bcron\b', "Cron reference"),
    (r'\bsystemd\b', "Systemd reference"),
    (r'\bservice\b.*\b(start|enable|restart)\b', "Service manipulation"),
    (r'ExecStart\s*=', "ExecStart directive"),
    (r'rc\.local', "rc.local reference"),
    (r'\bLD_PRELOAD\b', "LD_PRELOAD reference"),
    (r'ssh-rsa\b', "SSH public key"),
    (r'authorized_keys', "Authorized keys reference"),
    (r'\.bashrc\b', "bashrc reference"),
    (r'\.profile\b', "profile reference"),
]

# IP address and connection patterns
IP_CONNECTION_PATTERNS = [
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', "IP:port pattern"),
    (r'/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "/dev/tcp with IP"),
    (r'connect\s*\(\s*["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Connect to IP"),
]

# Reverse shell patterns (expanded)
REVERSE_SHELL_PATTERNS = [
    (r'bash\s+-i\s+>&', "Bash -i redirect"),
    (r'/dev/tcp/\S+/\d+', "/dev/tcp connection"),
    (r'nc\s+\S+\s+\d+\s+-e', "Netcat -e reverse shell"),
    (r'nc\s+-e\s+/bin/', "Netcat execute shell"),
    (r'\bsocat\b.*EXEC', "Socat EXEC"),
    (r'python\s+-c\s+[\'"]import\s+(socket|os)', "Python inline socket/os import"),
    (r'perl\s+-e\s+.*socket', "Perl inline socket"),
    (r'ruby\s+-rsocket', "Ruby socket require"),
    (r'php\s+-r\s+.*fsockopen', "PHP inline fsockopen"),
    (r'mkfifo.*nc\s+', "Named pipe netcat"),
    (r'telnet\s+\S+\s+\d+\s*\|', "Telnet piped"),
]

# NPM backdoor patterns
NPM_BACKDOOR_PATTERNS = [
    (r'"preinstall"\s*:', "NPM preinstall script"),
    (r'"postinstall"\s*:', "NPM postinstall script"),
    (r'"install"\s*:\s*"[^"]*curl', "NPM install with curl"),
    (r'"install"\s*:\s*"[^"]*wget', "NPM install with wget"),
    (r'"install"\s*:\s*"[^"]*bash', "NPM install with bash"),
    (r'"scripts"\s*:.*"[^"]*>/dev/null', "NPM script output suppression"),
]

# Python backdoor patterns
PYTHON_BACKDOOR_PATTERNS = [
    (r'setup\s*\(', "Python setup.py function"),
    (r'cmdclass\s*=', "Python setup cmdclass hook"),
    (r'from\s+setuptools\s+import', "Setuptools import"),
    (r'sitecustomize', "Python sitecustomize hook"),
    (r'usercustomize', "Python usercustomize hook"),
    (r'__import__\s*\(\s*["\']', "Dynamic import"),
    (r'importlib\.import_module', "Dynamic module import"),
]

# Makefile backdoor patterns
MAKEFILE_BACKDOOR_PATTERNS = [
    (r'^\s*\$\(shell.*curl', "Makefile shell curl"),
    (r'^\s*\$\(shell.*wget', "Makefile shell wget"),
    (r'^\s*\$\(shell.*bash\s+-', "Makefile shell bash"),
    (r'^\s*\$\(shell.*python', "Makefile shell python"),
    (r'^\s*\$\(shell.*nc\s+-', "Makefile shell netcat"),
    (r'@curl\b', "Makefile curl command"),
    (r'@wget\b', "Makefile wget command"),
    (r'`curl\b', "Makefile backtick curl"),
    (r'`wget\b', "Makefile backtick wget"),
]

# SSHD config security patterns
SSHD_CONFIG_PATTERNS = [
    (r'PermitRootLogin\s+(yes|without-password|prohibit-password)', "Root login enabled"),
    (r'PasswordAuthentication\s+yes', "Password auth enabled"),
    (r'PermitEmptyPasswords\s+yes', "Empty passwords allowed"),
    (r'AuthorizedKeysFile\s+(?!.*\.ssh/authorized_keys)', "Non-standard authorized_keys location"),
    (r'AuthorizedKeysCommand\s+', "AuthorizedKeysCommand configured"),
    (r'ForceCommand\s+', "ForceCommand configured"),
    (r'PermitTunnel\s+yes', "Tunneling enabled"),
    (r'GatewayPorts\s+yes', "Gateway ports enabled"),
    (r'AllowTcpForwarding\s+yes', "TCP forwarding enabled"),
    (r'X11Forwarding\s+yes', "X11 forwarding enabled"),
]

# Docker/container persistence patterns
DOCKER_PERSISTENCE_PATTERNS = [
    (r'"Binds"\s*:\s*\[.*:/host', "Docker bind mount to host"),
    (r'"Binds"\s*:\s*\[.*/etc', "Docker bind mount to /etc"),
    (r'"Binds"\s*:\s*\[.*/root', "Docker bind mount to /root"),
    (r'"Binds"\s*:\s*\[.*/var/run/docker', "Docker socket mount"),
    (r'"Privileged"\s*:\s*true', "Privileged container"),
    (r'"HostConfig".*"Privileged"', "Privileged host config"),
    (r'--privileged', "Privileged flag"),
    (r'-v\s+/:/host', "Root filesystem mount"),
    (r'docker\.sock', "Docker socket reference"),
]

# Environment persistence patterns
ENVIRONMENT_PERSISTENCE_PATTERNS = [
    (r'^[A-Z_]+=.*\|', "Environment var with pipe"),
    (r'^[A-Z_]+=.*\$\(', "Environment var with command substitution"),
    (r'^[A-Z_]+=.*`', "Environment var with backticks"),
    (r'LD_PRELOAD\s*=', "LD_PRELOAD in environment"),
    (r'LD_LIBRARY_PATH\s*=.*/tmp', "LD_LIBRARY_PATH pointing to /tmp"),
    (r'LD_LIBRARY_PATH\s*=.*/dev/shm', "LD_LIBRARY_PATH pointing to /dev/shm"),
    (r'PATH\s*=.*/tmp', "PATH containing /tmp"),
    (r'PATH\s*=.*/dev/shm', "PATH containing /dev/shm"),
]


# ============================================================================
# Path Security
# ============================================================================

def is_safe_path(base_path: str, target_path: str) -> bool:
    try:
        base_resolved = os.path.realpath(base_path)
        target_resolved = os.path.realpath(os.path.join(base_path, target_path))
        return target_resolved.startswith(base_resolved + os.sep) or target_resolved == base_resolved
    except (OSError, ValueError):
        return False


def safe_extract_member(tar: tarfile.TarFile, member: tarfile.TarInfo, 
                        extract_path: str) -> Optional[bytes]:
    member_path = os.path.normpath(member.name)
    if member_path.startswith('..') or member_path.startswith('/'):
        member_path = member_path.lstrip('/')
        while member_path.startswith('../'):
            member_path = member_path[3:]
    
    full_path = os.path.join(extract_path, member_path)
    if not is_safe_path(extract_path, member_path):
        return None
    
    try:
        f = tar.extractfile(member)
        if f is None:
            return None
        return f.read()
    except Exception:
        return None


# ============================================================================
# UAC Tarball Handler
# ============================================================================

class UACHandler:
    """Handler for reading files from UAC tarballs or directories."""
    
    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')
    
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.is_tarball = self._is_tarball(source_path)
        self.tar = None
        self.root_prefix = ""
        
        if self.is_tarball:
            self._open_tarball()
    
    def _is_tarball(self, path: str) -> bool:
        return any(path.lower().endswith(ext) for ext in self.TAR_EXTENSIONS)
    
    def _open_tarball(self):
        try:
            if self.source_path.endswith('.gz') or self.source_path.endswith('.tgz'):
                self.tar = tarfile.open(self.source_path, 'r:gz')
            elif self.source_path.endswith('.bz2') or self.source_path.endswith('.tbz2'):
                self.tar = tarfile.open(self.source_path, 'r:bz2')
            else:
                self.tar = tarfile.open(self.source_path, 'r:')
            
            # Detect root prefix
            for member in self.tar.getmembers()[:100]:
                if '/var/' in member.name or '/etc/' in member.name:
                    idx = member.name.find('/var/') if '/var/' in member.name else member.name.find('/etc/')
                    if idx > 0:
                        self.root_prefix = member.name[:idx]
                    break
        except Exception as e:
            raise RuntimeError(f"Failed to open tarball: {e}")
    
    def close(self):
        if self.tar:
            self.tar.close()
    
    def get_file(self, path: str) -> Optional[bytes]:
        """Get file contents."""
        if self.is_tarball:
            return self._get_file_tarball(path)
        else:
            return self._get_file_directory(path)
    
    def _get_file_tarball(self, path: str) -> Optional[bytes]:
        if not self.tar:
            return None
        
        paths_to_try = [path.lstrip('/')]
        if self.root_prefix:
            paths_to_try.append(f"{self.root_prefix}/{path.lstrip('/')}")
        
        for p in paths_to_try:
            try:
                member = self.tar.getmember(p)
                return safe_extract_member(self.tar, member, "/tmp")
            except KeyError:
                continue
        return None
    
    def _get_file_directory(self, path: str) -> Optional[bytes]:
        full_path = os.path.join(self.source_path, path.lstrip('/'))
        if os.path.isfile(full_path):
            try:
                with open(full_path, 'rb') as f:
                    return f.read()
            except Exception:
                return None
        return None
    
    def find_files(self, patterns: List[str]) -> List[Tuple[str, Optional[tarfile.TarInfo]]]:
        """Find files matching patterns."""
        if self.is_tarball:
            return self._find_files_tarball(patterns)
        else:
            return self._find_files_directory(patterns)
    
    def _find_files_tarball(self, patterns: List[str]) -> List[Tuple[str, Optional[tarfile.TarInfo]]]:
        results = []
        if not self.tar:
            return results
        
        for member in self.tar.getmembers():
            if not member.isfile():
                continue
            for pattern in patterns:
                if pattern in member.name or re.search(pattern, member.name):
                    # Normalize path
                    normalized = member.name
                    if self.root_prefix and normalized.startswith(self.root_prefix):
                        normalized = normalized[len(self.root_prefix):]
                    results.append((normalized, member))
                    break
        return results
    
    def _find_files_directory(self, patterns: List[str]) -> List[Tuple[str, None]]:
        results = []
        for root, dirs, files in os.walk(self.source_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                relative = os.path.relpath(filepath, self.source_path)
                for pattern in patterns:
                    if pattern in relative or re.search(pattern, relative):
                        results.append(('/' + relative, None))
                        break
        return results
    
    def get_members(self) -> List:
        """Get all members/files."""
        if self.is_tarball and self.tar:
            return self.tar.getmembers()
        return []
    
    def list_directory(self, path: str) -> List[str]:
        """List directory contents."""
        if self.is_tarball:
            return self._list_dir_tarball(path)
        else:
            return self._list_dir_directory(path)
    
    def _list_dir_tarball(self, path: str) -> List[str]:
        results = []
        if not self.tar:
            return results
        
        path = path.lstrip('/').rstrip('/') + '/'
        for member in self.tar.getmembers():
            member_path = member.name
            if self.root_prefix:
                if member_path.startswith(self.root_prefix):
                    member_path = member_path[len(self.root_prefix):]
            member_path = member_path.lstrip('/')
            
            if member_path.startswith(path):
                remainder = member_path[len(path):]
                if remainder and '/' not in remainder.rstrip('/'):
                    results.append(member_path)
        return results
    
    def _list_dir_directory(self, path: str) -> List[str]:
        results = []
        full_path = os.path.join(self.source_path, path.lstrip('/'))
        if os.path.isdir(full_path):
            for item in os.listdir(full_path):
                results.append(os.path.join(path, item))
        return results


# ============================================================================
# Hash Calculation
# ============================================================================

def calculate_hashes(data: bytes) -> Tuple[str, str]:
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


# ============================================================================
# Detection Functions
# ============================================================================

class PersistenceHunter:
    """Main persistence detection class."""
    
    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path) if source_path != "/" else "/"
        self.handler = UACHandler(source_path)
        self.findings: List[PersistenceFinding] = []
        self.stats = defaultdict(int)
    
    def close(self):
        self.handler.close()
    
    def hunt(self, verbose: bool = True) -> None:
        """Run all detection checks."""
        Style.enable_windows_ansi()
        
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}  Linux Persistence Hunter v{__version__}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}  PANIX-Style Persistence Detection{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Source:{Style.RESET} {self.source_path}", file=sys.stderr)
        
        checks = [
            ("Cron Jobs", self._check_cron),
            ("At Jobs", self._check_at_jobs),
            ("Systemd Timers", self._check_systemd_timers),
            ("SSH Authorized Keys", self._check_authorized_keys),
            ("Backdoor Users (/etc/passwd)", self._check_passwd_backdoors),
            ("Systemd Services", self._check_systemd_services),
            ("Init.d Scripts", self._check_initd),
            ("RC.local", self._check_rc_local),
            ("Shell Profiles", self._check_shell_profiles),
            ("LD_PRELOAD Hijacking", self._check_ld_preload),
            ("PAM Configuration", self._check_pam),
            ("Sudoers", self._check_sudoers),
            ("SUID/SGID Binaries", self._check_suid),
            ("Capabilities", self._check_capabilities),
            ("Udev Rules", self._check_udev),
            ("XDG Autostart", self._check_xdg_autostart),
            ("MOTD Scripts", self._check_motd),
            ("Git Hooks", self._check_git_hooks),
            ("Web Shells", self._check_web_shells),
            ("Kernel Modules", self._check_kernel_modules),
            ("Rootkit Indicators", self._check_rootkit_indicators),
            ("Container Escape", self._check_container_escape),
            ("NetworkManager Dispatcher", self._check_network_manager),
            ("D-Bus Services", self._check_dbus),
            ("Polkit Rules", self._check_polkit),
            ("Package Manager Hooks", self._check_package_hooks),
            ("GRUB Config", self._check_grub),
            ("Initramfs", self._check_initramfs),
            # Additional checks from Elastic Security Labs series
            ("Systemd Generators", self._check_systemd_generators),
            ("Systemd Socket Activation", self._check_socket_activation),
            ("Shadow File", self._check_shadow_file),
            ("Trap Commands", self._check_trap_commands),
            ("Message Queues", self._check_message_queues),
            ("eBPF Programs", self._check_ebpf),
            ("Dynamic Linker Cache", self._check_ld_cache),
            # NEW: Extended detection checks
            ("SSHD Config", self._check_sshd_config),
            ("Environment Persistence", self._check_environment_persistence),
            ("Docker Persistence", self._check_docker_persistence),
            ("Modprobe/Kernel Modules Config", self._check_modprobe_modules),
            ("Dracut Modules", self._check_dracut),
            ("Sketchy Code Patterns", self._check_sketchy_code),
            ("NPM Package Backdoors", self._check_npm_backdoors),
            ("Python Backdoors", self._check_python_backdoors),
            ("Makefile Backdoors", self._check_makefiles),
            ("IP Connection Patterns", self._check_ip_connections),
            ("Active Git Hooks", self._check_git_hooks_active),
        ]
        
        for i, (name, check_func) in enumerate(checks, 1):
            if verbose:
                print(f"\n{Style.INFO}[{i}/{len(checks)}] Checking {name}...{Style.RESET}", file=sys.stderr)
            try:
                count = check_func()
                if verbose and count > 0:
                    print(f"  {Style.WARNING}Found {count} suspicious items{Style.RESET}", file=sys.stderr)
            except Exception as e:
                if verbose:
                    print(f"  {Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        
        if verbose:
            self._print_summary()
    
    def _add_finding(self, filepath: str, technique_key: str, severity: str,
                     description: str, indicator: str = "", line_number: int = 0,
                     raw_content: str = "", extra_info: Dict = None) -> None:
        """Add a finding."""
        technique, technique_id = MITRE_MAPPINGS.get(technique_key, (technique_key, "N/A"))
        
        self.findings.append(PersistenceFinding(
            filepath=filepath,
            technique=technique,
            technique_id=technique_id,
            severity=severity,
            description=description,
            indicator=indicator,
            line_number=line_number,
            raw_content=raw_content,
            extra_info=extra_info or {}
        ))
        self.stats[technique_key] += 1
    
    def _check_content_patterns(self, filepath: str, content: str, 
                                 patterns: List[Tuple[str, str]], 
                                 technique_key: str) -> int:
        """Check content against patterns."""
        count = 0
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(
                        filepath=filepath,
                        technique_key=technique_key,
                        severity="HIGH",
                        description=desc,
                        indicator=pattern,
                        line_number=line_num,
                        raw_content=line[:500]
                    )
                    count += 1
        return count
    
    # ========================================================================
    # Cron Detection
    # ========================================================================
    
    def _check_cron(self) -> int:
        """Check cron configurations - extracts ALL cron entries for review."""
        count = 0
        
        # Crontab-format files (contain time schedules + commands)
        crontab_paths = [
            "etc/crontab",
            "etc/cron.d/",
            "var/spool/cron/",
            "var/spool/cron/crontabs/",
        ]
        
        # Script directories (contain executable scripts, run by run-parts)
        # These are NOT crontab format - they're shell scripts
        script_dirs = {
            "etc/cron.hourly/": "Hourly",
            "etc/cron.daily/": "Daily", 
            "etc/cron.weekly/": "Weekly",
            "etc/cron.monthly/": "Monthly",
        }
        
        # Process crontab-format files
        for cron_path in crontab_paths:
            files = self.handler.list_directory(cron_path) if cron_path.endswith('/') else [cron_path]
            
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Extract ALL cron entries for review
                for line_num, line in enumerate(content.split('\n'), 1):
                    line_stripped = line.strip()
                    
                    # Skip empty lines and comments
                    if not line_stripped or line_stripped.startswith('#'):
                        continue
                    
                    # Skip variable assignments that aren't commands
                    if '=' in line_stripped and not any(c in line_stripped for c in ['*', '/', '@']):
                        # But still log environment variables for context
                        if any(v in line_stripped.upper() for v in ['PATH=', 'SHELL=', 'MAILTO=']):
                            continue
                    
                    # Determine severity based on patterns
                    severity = "INFO"  # Default: just for review
                    description = "Cron entry"
                    
                    # Check for suspicious patterns to elevate severity
                    for pattern, desc in CRON_SUSPICIOUS_PATTERNS + SHELL_BACKDOOR_PATTERNS:
                        if re.search(pattern, line_stripped, re.IGNORECASE):
                            severity = "HIGH"
                            description = f"Suspicious cron: {desc}"
                            break
                    
                    # Determine cron type from path
                    if 'var/spool/cron' in filepath:
                        description = f"User cron: {description}" if severity != "INFO" else "User crontab entry"
                    elif 'cron.d' in filepath:
                        description = f"System cron.d: {description}" if severity != "INFO" else "System cron.d entry"
                    elif 'crontab' in filepath:
                        description = f"System crontab: {description}" if severity != "INFO" else "System crontab entry"
                    
                    self._add_finding(
                        filepath=filepath,
                        technique_key="cron",
                        severity=severity,
                        description=description,
                        indicator=line_stripped[:200],
                        line_number=line_num,
                        raw_content=line[:500]
                    )
                    count += 1
        
        # Process script directories (cron.daily, cron.hourly, etc.)
        # These contain executable scripts, not crontab entries
        for script_dir, schedule in script_dirs.items():
            files = self.handler.list_directory(script_dir)
            
            for filepath in files:
                # Get the script name
                script_name = os.path.basename(filepath)
                
                # Skip placeholder files and common non-script files
                if script_name in ['.placeholder', 'README', '.gitkeep']:
                    continue
                
                # Get first few lines of script for context
                data = self.handler.get_file(filepath)
                script_preview = ""
                if data:
                    try:
                        content = data.decode('utf-8', errors='replace')
                        # Get first non-empty, non-shebang line as preview
                        for line in content.split('\n')[:10]:
                            line = line.strip()
                            if line and not line.startswith('#!') and not line.startswith('#'):
                                script_preview = line[:100]
                                break
                    except Exception:
                        pass
                
                # Check for suspicious patterns in the script
                severity = "INFO"
                description = f"{schedule} cron script"
                
                if data:
                    try:
                        content = data.decode('utf-8', errors='replace')
                        for pattern, desc in SHELL_BACKDOOR_PATTERNS + CRON_SUSPICIOUS_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                severity = "HIGH"
                                description = f"{schedule} cron script - SUSPICIOUS: {desc}"
                                break
                    except Exception:
                        pass
                
                self._add_finding(
                    filepath=filepath,
                    technique_key="cron",
                    severity=severity,
                    description=description,
                    indicator=f"Script: {script_name}" + (f" | {script_preview}" if script_preview else ""),
                    raw_content=script_name
                )
                count += 1
        
        return count
    
    # ========================================================================
    # At Jobs Detection
    # ========================================================================
    
    def _check_at_jobs(self) -> int:
        """Check at jobs - extracts ALL at jobs for review."""
        count = 0
        
        at_paths = ["var/spool/at/", "var/spool/atjobs/"]
        
        for at_path in at_paths:
            files = self.handler.list_directory(at_path)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Log the at job file itself
                self._add_finding(
                    filepath=filepath,
                    technique_key="at_job",
                    severity="INFO",
                    description="At job file found",
                    indicator=os.path.basename(filepath),
                    raw_content=content[:1000]
                )
                count += 1
                
                # Also check for suspicious patterns and elevate severity
                for line_num, line in enumerate(content.split('\n'), 1):
                    for pattern, desc in SHELL_BACKDOOR_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="at_job",
                                severity="HIGH",
                                description=f"Suspicious at job: {desc}",
                                indicator=line[:200].strip(),
                                line_number=line_num,
                                raw_content=line[:500]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # Systemd Timers
    # ========================================================================
    
    def _check_systemd_timers(self) -> int:
        """Check systemd timers - extracts ALL timers for review."""
        count = 0
        
        # System-level timer paths
        timer_paths = [
            "etc/systemd/system/",
            "usr/lib/systemd/system/",
            "lib/systemd/system/",
            "run/systemd/system/",
            "etc/systemd/user/",
            "usr/lib/systemd/user/",
        ]
        
        # Also check user-level timers in home directories
        # These are at ~/.config/systemd/user/
        home_dirs = self.handler.list_directory("home/")
        for home_dir in home_dirs:
            user_timer_path = f"{home_dir}/.config/systemd/user/"
            timer_paths.append(user_timer_path)
        
        # Also check root's user timers
        timer_paths.append("root/.config/systemd/user/")
        
        for timer_path in timer_paths:
            files = self.handler.list_directory(timer_path)
            for filepath in files:
                if not filepath.endswith('.timer'):
                    continue
                
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Extract timer schedule info
                on_calendar = ""
                on_boot = ""
                description_line = ""
                for line in content.split('\n'):
                    if line.strip().startswith('OnCalendar='):
                        on_calendar = line.strip()
                    elif line.strip().startswith('OnBootSec=') or line.strip().startswith('OnUnitActiveSec='):
                        on_boot = line.strip()
                    elif line.strip().startswith('Description='):
                        description_line = line.strip()
                
                schedule_info = on_calendar or on_boot or "Schedule not found"
                
                # Log the timer
                self._add_finding(
                    filepath=filepath,
                    technique_key="timer",
                    severity="INFO",
                    description=f"Systemd timer: {description_line}" if description_line else "Systemd timer",
                    indicator=schedule_info,
                    raw_content=content[:1000]
                )
                count += 1
                
                # Check associated service file
                service_path = filepath.replace('.timer', '.service')
                service_data = self.handler.get_file(service_path)
                if service_data:
                    try:
                        service_content = service_data.decode('utf-8', errors='replace')
                        
                        # Extract ExecStart for review
                        for line_num, line in enumerate(service_content.split('\n'), 1):
                            if line.strip().startswith('ExecStart='):
                                exec_cmd = line.strip()
                                
                                # Check for suspicious patterns
                                severity = "INFO"
                                desc = "Timer service ExecStart"
                                for pattern, pattern_desc in SHELL_BACKDOOR_PATTERNS + SYSTEMD_SUSPICIOUS_PATTERNS:
                                    if re.search(pattern, exec_cmd, re.IGNORECASE):
                                        severity = "HIGH"
                                        desc = f"Suspicious timer service: {pattern_desc}"
                                        break
                                
                                self._add_finding(
                                    filepath=service_path,
                                    technique_key="timer",
                                    severity=severity,
                                    description=desc,
                                    indicator=exec_cmd[:200],
                                    line_number=line_num,
                                    raw_content=line[:500]
                                )
                                count += 1
                    except Exception:
                        pass
        
        return count
    
    # ========================================================================
    # SSH Authorized Keys
    # ========================================================================
    
    def _check_authorized_keys(self) -> int:
        """Check for suspicious authorized_keys entries."""
        count = 0
        
        # Find all authorized_keys files
        auth_key_files = self.handler.find_files([r'authorized_keys', r'authorized_keys2'])
        
        for filepath, member in auth_key_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            
            for line_num, line in enumerate(lines, 1):
                # Check for command= option (could be backdoor)
                if 'command=' in line:
                    self._add_finding(
                        filepath=filepath,
                        technique_key="authorized_keys",
                        severity="HIGH",
                        description="SSH key with forced command - potential backdoor",
                        indicator="command=",
                        line_number=line_num,
                        raw_content=line[:200]
                    )
                    count += 1
                
                # Check for environment= option
                if 'environment=' in line:
                    self._add_finding(
                        filepath=filepath,
                        technique_key="authorized_keys",
                        severity="MEDIUM",
                        description="SSH key with environment modification",
                        indicator="environment=",
                        line_number=line_num,
                        raw_content=line[:200]
                    )
                    count += 1
                
                # Check for from= restriction bypass
                if 'no-' in line and 'permitopen' not in line:
                    # Multiple no-* options might indicate restriction bypass attempts
                    if line.count('no-') >= 3:
                        self._add_finding(
                            filepath=filepath,
                            technique_key="authorized_keys",
                            severity="LOW",
                            description="SSH key with multiple restrictions (review)",
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # Passwd Backdoors
    # ========================================================================
    
    def _check_passwd_backdoors(self) -> int:
        """Check /etc/passwd for backdoor users."""
        count = 0
        
        passwd_data = self.handler.get_file("etc/passwd")
        if not passwd_data:
            return count
        
        try:
            content = passwd_data.decode('utf-8', errors='replace')
        except Exception:
            return count
        
        # Known system accounts with UID 0
        known_root = {'root'}
        
        for line_num, line in enumerate(content.split('\n'), 1):
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(':')
            if len(parts) < 7:
                continue
            
            username = parts[0]
            uid = parts[2]
            gid = parts[3]
            shell = parts[6]
            
            # Check for additional UID=0 users
            if uid == '0' and username not in known_root:
                self._add_finding(
                    filepath="etc/passwd",
                    technique_key="backdoor_user",
                    severity="CRITICAL",
                    description=f"Non-root user with UID=0: {username}",
                    indicator=f"uid=0",
                    line_number=line_num,
                    raw_content=line
                )
                count += 1
            
            # Check for UID=0 GID=0 users with shell
            if uid == '0' and gid == '0' and shell in ['/bin/bash', '/bin/sh', '/bin/zsh']:
                if username not in known_root:
                    self._add_finding(
                        filepath="etc/passwd",
                        technique_key="backdoor_user",
                        severity="CRITICAL",
                        description=f"Root-equivalent user with shell: {username}",
                        indicator=f"uid=0,gid=0,shell={shell}",
                        line_number=line_num,
                        raw_content=line
                    )
                    count += 1
            
            # Check for system users with login shells (shouldn't have)
            system_nologin_users = ['daemon', 'bin', 'sys', 'games', 'man', 'lp', 
                                     'mail', 'news', 'uucp', 'proxy', 'www-data',
                                     'backup', 'list', 'irc', 'gnats', 'nobody',
                                     'systemd-network', 'systemd-resolve', 'syslog',
                                     'messagebus', 'uuidd', 'dnsmasq', 'sshd']
            
            if username in system_nologin_users and shell in ['/bin/bash', '/bin/sh', '/bin/zsh']:
                self._add_finding(
                    filepath="etc/passwd",
                    technique_key="backdoor_user",
                    severity="HIGH",
                    description=f"System user with login shell: {username}",
                    indicator=f"shell={shell}",
                    line_number=line_num,
                    raw_content=line
                )
                count += 1
            
            # Check for password in passwd file (old style)
            password_field = parts[1]
            if password_field and password_field not in ['x', '*', '!', '!!']:
                self._add_finding(
                    filepath="etc/passwd",
                    technique_key="passwd",
                    severity="HIGH",
                    description=f"Password hash in /etc/passwd for {username}",
                    indicator="password_in_passwd",
                    line_number=line_num,
                    raw_content=line
                )
                count += 1
        
        return count
    
    # ========================================================================
    # Systemd Services
    # ========================================================================
    
    def _check_systemd_services(self) -> int:
        """Check systemd services - extracts ALL services for review."""
        count = 0
        
        # System-level service paths
        systemd_paths = [
            "etc/systemd/system/",
            "usr/lib/systemd/system/",
            "lib/systemd/system/",
            "run/systemd/system/",
            "etc/systemd/user/",
            "usr/lib/systemd/user/",
        ]
        
        # Also check user-level services in home directories
        # These are at ~/.config/systemd/user/
        home_dirs = self.handler.list_directory("home/")
        for home_dir in home_dirs:
            user_service_path = f"{home_dir}/.config/systemd/user/"
            systemd_paths.append(user_service_path)
        
        # Also check root's user services
        systemd_paths.append("root/.config/systemd/user/")
        
        for sys_path in systemd_paths:
            files = self.handler.list_directory(sys_path)
            for filepath in files:
                if not filepath.endswith('.service'):
                    continue
                
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Extract service info
                description_line = ""
                exec_start = ""
                wanted_by = ""
                
                for line in content.split('\n'):
                    line_stripped = line.strip()
                    if line_stripped.startswith('Description='):
                        description_line = line_stripped.split('=', 1)[1] if '=' in line_stripped else ""
                    elif line_stripped.startswith('ExecStart='):
                        exec_start = line_stripped.split('=', 1)[1] if '=' in line_stripped else ""
                    elif line_stripped.startswith('WantedBy='):
                        wanted_by = line_stripped.split('=', 1)[1] if '=' in line_stripped else ""
                
                # Log all ExecStart entries for review
                for line_num, line in enumerate(content.split('\n'), 1):
                    line_stripped = line.strip()
                    
                    if line_stripped.startswith('ExecStart=') or line_stripped.startswith('ExecStartPre=') or line_stripped.startswith('ExecStartPost='):
                        cmd = line_stripped.split('=', 1)[1] if '=' in line_stripped else ""
                        
                        # Determine severity
                        severity = "INFO"
                        desc = f"Service: {description_line}" if description_line else "Systemd service"
                        
                        # Check for suspicious paths
                        if any(p in cmd for p in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                            severity = "HIGH"
                            desc = f"Suspicious path in service: {description_line}" if description_line else "Service from suspicious path"
                        
                        # Check for suspicious patterns
                        for pattern, pattern_desc in SHELL_BACKDOOR_PATTERNS + SYSTEMD_SUSPICIOUS_PATTERNS:
                            if re.search(pattern, line_stripped, re.IGNORECASE):
                                severity = "HIGH"
                                desc = f"Suspicious service: {pattern_desc}"
                                break
                        
                        # Categorize by location
                        if 'etc/systemd/system' in filepath:
                            location = "Custom (etc/systemd/system)"
                        elif 'etc/systemd/user' in filepath:
                            location = "User service"
                        else:
                            location = "System default"
                        
                        self._add_finding(
                            filepath=filepath,
                            technique_key="systemd",
                            severity=severity,
                            description=f"{desc} [{location}]",
                            indicator=cmd[:200],
                            line_number=line_num,
                            raw_content=line[:500],
                            extra_info={"wanted_by": wanted_by}
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # Init.d Scripts
    # ========================================================================
    
    def _check_initd(self) -> int:
        """Check init.d scripts for persistence."""
        count = 0
        
        initd_files = self.handler.list_directory("etc/init.d/")
        
        for filepath in initd_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   SHELL_BACKDOOR_PATTERNS,
                                                   "initd")
        
        return count
    
    # ========================================================================
    # RC.local
    # ========================================================================
    
    def _check_rc_local(self) -> int:
        """Check rc.local for persistence."""
        count = 0
        
        rc_files = ["etc/rc.local", "etc/rc.d/rc.local"]
        
        for rc_path in rc_files:
            data = self.handler.get_file(rc_path)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Any non-trivial content in rc.local is suspicious on modern systems
            lines = [l for l in content.split('\n') if l.strip() and not l.startswith('#')]
            
            if len(lines) > 1:  # More than just 'exit 0'
                count += self._check_content_patterns(rc_path, content,
                                                       SHELL_BACKDOOR_PATTERNS,
                                                       "rc_local")
                
                # Flag if rc.local has significant content
                self._add_finding(
                    filepath=rc_path,
                    technique_key="rc_local",
                    severity="MEDIUM",
                    description=f"rc.local contains {len(lines)} lines of commands",
                    raw_content='\n'.join(lines[:5])
                )
                count += 1
        
        return count
    
    # ========================================================================
    # Shell Profiles
    # ========================================================================
    
    def _check_shell_profiles(self) -> int:
        """Check shell profiles for backdoors."""
        count = 0
        
        profile_patterns = [
            r'\.bashrc$',
            r'\.bash_profile$',
            r'\.profile$',
            r'\.zshrc$',
            r'\.zprofile$',
            r'\.cshrc$',
            r'etc/profile$',
            r'etc/profile\.d/',
            r'etc/bash\.bashrc$',
            r'etc/bashrc$',
            r'etc/zsh/',
        ]
        
        files = self.handler.find_files(profile_patterns)
        
        for filepath, member in files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   SHELL_BACKDOOR_PATTERNS,
                                                   "shell_profile")
        
        return count
    
    # ========================================================================
    # LD_PRELOAD Hijacking
    # ========================================================================
    
    def _check_ld_preload(self) -> int:
        """Check for LD_PRELOAD hijacking."""
        count = 0
        
        # Check /etc/ld.so.preload
        preload_data = self.handler.get_file("etc/ld.so.preload")
        if preload_data:
            try:
                content = preload_data.decode('utf-8', errors='replace')
                lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
                
                for line_num, lib in enumerate(lines, 1):
                    self._add_finding(
                        filepath="etc/ld.so.preload",
                        technique_key="ld_preload",
                        severity="CRITICAL",
                        description=f"Library preload configured: {lib}",
                        indicator=lib,
                        line_number=line_num
                    )
                    count += 1
            except Exception:
                pass
        
        # Check ld.so.conf for suspicious paths
        for conf_file in ["etc/ld.so.conf"] + self.handler.list_directory("etc/ld.so.conf.d/"):
            data = self.handler.get_file(conf_file)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('include'):
                    continue
                
                # Suspicious library paths
                if any(p in line for p in ['/tmp', '/var/tmp', '/dev/shm', '/home']):
                    self._add_finding(
                        filepath=conf_file,
                        technique_key="ld_preload",
                        severity="HIGH",
                        description=f"Suspicious library path in ld.so.conf",
                        indicator=line,
                        line_number=line_num
                    )
                    count += 1
        
        return count
    
    # ========================================================================
    # PAM Configuration
    # ========================================================================
    
    def _check_pam(self) -> int:
        """Check PAM configuration for backdoors."""
        count = 0
        
        pam_files = self.handler.list_directory("etc/pam.d/")
        
        for filepath in pam_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   PAM_BACKDOOR_PATTERNS,
                                                   "pam")
        
        # Also check for pam_exec scripts
        pam_exec_scripts = self.handler.find_files([r'pam.*\.sh$', r'pam_script'])
        for filepath, member in pam_exec_scripts:
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    count += self._check_content_patterns(filepath, content,
                                                           SHELL_BACKDOOR_PATTERNS,
                                                           "pam")
                except Exception:
                    pass
        
        return count
    
    # ========================================================================
    # Sudoers
    # ========================================================================
    
    def _check_sudoers(self) -> int:
        """Check sudoers configuration for backdoors."""
        count = 0
        
        sudoers_files = ["etc/sudoers"] + self.handler.list_directory("etc/sudoers.d/")
        
        for filepath in sudoers_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   SUDOERS_BACKDOOR_PATTERNS,
                                                   "sudoers")
        
        return count
    
    # ========================================================================
    # SUID/SGID
    # ========================================================================
    
    def _check_suid(self) -> int:
        """Check for suspicious SUID/SGID binaries."""
        count = 0
        
        KNOWN_SUID = {
            '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/newgrp',
            '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/gpasswd', '/bin/ping',
            '/usr/bin/ping', '/bin/mount', '/bin/umount', '/usr/bin/mount',
            '/usr/bin/umount', '/usr/lib/openssh/ssh-keysign',
            '/usr/libexec/openssh/ssh-keysign', '/usr/bin/pkexec',
            '/usr/bin/crontab', '/usr/bin/at', '/usr/bin/wall',
        }
        
        if self.handler.is_tarball and self.handler.tar:
            for member in self.handler.tar.getmembers():
                if not member.isfile():
                    continue
                
                is_suid = bool(member.mode & stat.S_ISUID)
                is_sgid = bool(member.mode & stat.S_ISGID)
                
                if is_suid or is_sgid:
                    # Normalize path
                    normalized = '/' + member.name.lstrip('/')
                    if self.handler.root_prefix and normalized.startswith('/' + self.handler.root_prefix):
                        normalized = normalized[len(self.handler.root_prefix) + 1:]
                    
                    # Check if known
                    is_known = any(normalized.endswith(k) for k in KNOWN_SUID)
                    
                    # Check if in suspicious location
                    is_suspicious = any(p in normalized for p in ['/tmp/', '/var/tmp/', '/dev/shm/', '/home/'])
                    
                    if not is_known or is_suspicious:
                        suid_type = []
                        if is_suid:
                            suid_type.append("SUID")
                        if is_sgid:
                            suid_type.append("SGID")
                        
                        severity = "CRITICAL" if is_suspicious else ("HIGH" if not is_known else "MEDIUM")
                        
                        self._add_finding(
                            filepath=normalized,
                            technique_key="suid",
                            severity=severity,
                            description=f"Unexpected {'+'.join(suid_type)} binary",
                            indicator=stat.filemode(member.mode),
                            extra_info={"size": member.size}
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # Capabilities
    # ========================================================================
    
    def _check_capabilities(self) -> int:
        """Check for binaries with dangerous capabilities."""
        count = 0
        
        # Look for capability database or output from getcap
        cap_files = self.handler.find_files([r'getcap', r'capabilities', r'filecaps'])
        
        dangerous_caps = [
            'cap_setuid', 'cap_setgid', 'cap_sys_admin', 'cap_sys_ptrace',
            'cap_dac_override', 'cap_dac_read_search', 'cap_net_admin',
            'cap_net_raw', 'cap_sys_module', 'cap_sys_rawio',
        ]
        
        for filepath, member in cap_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                for cap in dangerous_caps:
                    if cap in line.lower():
                        self._add_finding(
                            filepath=filepath,
                            technique_key="capabilities",
                            severity="HIGH",
                            description=f"Binary with dangerous capability: {cap}",
                            indicator=cap,
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
                        break
        
        return count
    
    # ========================================================================
    # Udev Rules
    # ========================================================================
    
    def _check_udev(self) -> int:
        """Check udev rules for persistence."""
        count = 0
        
        udev_dirs = ["etc/udev/rules.d/", "lib/udev/rules.d/", "usr/lib/udev/rules.d/"]
        
        for udev_dir in udev_dirs:
            files = self.handler.list_directory(udev_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                for line_num, line in enumerate(content.split('\n'), 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Check for RUN commands with suspicious content
                    if 'RUN' in line:
                        if any(p in line for p in ['/tmp/', '/var/tmp/', '/dev/shm/', 'bash', 'sh -c']):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="udev",
                                severity="HIGH",
                                description="Udev rule with suspicious RUN command",
                                indicator="RUN=",
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # XDG Autostart
    # ========================================================================
    
    def _check_xdg_autostart(self) -> int:
        """Check XDG autostart entries for persistence."""
        count = 0
        
        autostart_patterns = [r'\.config/autostart/', r'etc/xdg/autostart/']
        
        files = self.handler.find_files(autostart_patterns)
        
        for filepath, member in files:
            if not filepath.endswith('.desktop'):
                continue
            
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                if line.startswith('Exec='):
                    cmd = line[5:]
                    
                    # Check for suspicious commands
                    if any(p in cmd for p in ['/tmp/', '/var/tmp/', '/dev/shm/', 'curl', 'wget', 'nc ', 'ncat']):
                        self._add_finding(
                            filepath=filepath,
                            technique_key="xdg",
                            severity="HIGH",
                            description="XDG autostart with suspicious Exec command",
                            indicator=cmd[:100],
                            line_number=line_num,
                            raw_content=line
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # MOTD Scripts
    # ========================================================================
    
    def _check_motd(self) -> int:
        """Check MOTD scripts for persistence."""
        count = 0
        
        motd_dirs = ["etc/update-motd.d/", "etc/profile.d/"]
        
        for motd_dir in motd_dirs:
            files = self.handler.list_directory(motd_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                count += self._check_content_patterns(filepath, content,
                                                       SHELL_BACKDOOR_PATTERNS,
                                                       "motd")
        
        return count
    
    # ========================================================================
    # Git Hooks
    # ========================================================================
    
    def _check_git_hooks(self) -> int:
        """Check git hooks for persistence."""
        count = 0
        
        git_hook_files = self.handler.find_files([r'\.git/hooks/', r'\.git/config'])
        
        for filepath, member in git_hook_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Check for pager backdoors in config
            if 'config' in filepath:
                if 'pager' in content.lower() and any(s in content for s in ['!', '|', 'sh', 'bash']):
                    self._add_finding(
                        filepath=filepath,
                        technique_key="git_hook",
                        severity="HIGH",
                        description="Git config with potential pager backdoor",
                        raw_content=content[:200]
                    )
                    count += 1
            else:
                # Check hook scripts
                count += self._check_content_patterns(filepath, content,
                                                       SHELL_BACKDOOR_PATTERNS,
                                                       "git_hook")
        
        return count
    
    # ========================================================================
    # Web Shells
    # ========================================================================
    
    def _check_web_shells(self) -> int:
        """Check for web shells."""
        count = 0
        
        web_patterns = [r'\.php$', r'\.jsp$', r'\.asp$', r'\.aspx$', r'\.py$']
        web_dirs = ['var/www/', 'srv/www/', 'usr/share/nginx/', 'opt/']
        
        files = self.handler.find_files(web_patterns)
        
        for filepath, member in files:
            # Only check in web directories
            if not any(d in filepath for d in web_dirs):
                continue
            
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   WEB_SHELL_PATTERNS,
                                                   "web_shell")
        
        return count
    
    # ========================================================================
    # Kernel Modules
    # ========================================================================
    
    def _check_kernel_modules(self) -> int:
        """Check for suspicious kernel modules."""
        count = 0
        
        # Check modules.dep or loaded modules list
        module_files = self.handler.find_files([r'modules\.dep', r'proc/modules', r'lsmod'])
        
        suspicious_modules = ['diamorphine', 'reptile', 'jynx', 'azazel', 'suterusu', 
                             'adore', 'phalanx', 'brootus', 'bdvl', 'beurk']
        
        for filepath, member in module_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                for mod in suspicious_modules:
                    if mod in line.lower():
                        self._add_finding(
                            filepath=filepath,
                            technique_key="lkm",
                            severity="CRITICAL",
                            description=f"Suspicious kernel module: {mod}",
                            indicator=mod,
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # Rootkit Indicators
    # ========================================================================
    
    def _check_rootkit_indicators(self) -> int:
        """Check for known rootkit indicators."""
        count = 0
        
        # Check for common rootkit files/directories
        rootkit_paths = [
            '/dev/hdx1', '/dev/hdx2',  # Diamorphine
            '/dev/.udev/', '/dev/.static/',  # Hidden dev directories
            '/.hidden/', '/.backdoor/',
            '/usr/share/.hidden/', '/usr/lib/.hidden/',
        ]
        
        for rk_path in rootkit_paths:
            data = self.handler.get_file(rk_path.lstrip('/'))
            if data is not None:
                self._add_finding(
                    filepath=rk_path,
                    technique_key="rootkit",
                    severity="CRITICAL",
                    description=f"Known rootkit indicator path exists",
                    indicator=rk_path
                )
                count += 1
        
        # Search for rootkit-related strings in libraries
        lib_files = self.handler.find_files([r'libselinux', r'libc\.so', r'ld-linux'])
        
        for filepath, member in lib_files:
            # Check file size anomalies (trojaned libraries are often larger)
            if member and member.size > 5000000:  # > 5MB is suspicious for these
                self._add_finding(
                    filepath=filepath,
                    technique_key="rootkit",
                    severity="MEDIUM",
                    description=f"Library with unusual size: {member.size} bytes",
                    extra_info={"size": member.size}
                )
                count += 1
        
        return count
    
    # ========================================================================
    # Container Escape
    # ========================================================================
    
    def _check_container_escape(self) -> int:
        """Check for container escape configurations."""
        count = 0
        
        # Check docker socket exposure
        docker_files = self.handler.find_files([r'docker\.sock', r'docker-compose\.ya?ml'])
        
        for filepath, member in docker_files:
            if 'docker.sock' in filepath:
                self._add_finding(
                    filepath=filepath,
                    technique_key="malicious_container",
                    severity="HIGH",
                    description="Docker socket exposed",
                    indicator="docker.sock"
                )
                count += 1
            
            # Check compose files for privileged containers
            if 'compose' in filepath:
                data = self.handler.get_file(filepath)
                if data:
                    try:
                        content = data.decode('utf-8', errors='replace')
                        if 'privileged: true' in content or 'privileged:true' in content:
                            self._add_finding(
                                filepath=filepath,
                                technique_key="malicious_container",
                                severity="HIGH",
                                description="Docker compose with privileged container",
                                indicator="privileged: true"
                            )
                            count += 1
                    except Exception:
                        pass
        
        return count
    
    # ========================================================================
    # NetworkManager Dispatcher
    # ========================================================================
    
    def _check_network_manager(self) -> int:
        """Check NetworkManager dispatcher scripts."""
        count = 0
        
        dispatcher_files = self.handler.list_directory("etc/NetworkManager/dispatcher.d/")
        
        for filepath in dispatcher_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   SHELL_BACKDOOR_PATTERNS,
                                                   "network_manager")
        
        return count
    
    # ========================================================================
    # D-Bus Services
    # ========================================================================
    
    def _check_dbus(self) -> int:
        """Check D-Bus services for persistence."""
        count = 0
        
        dbus_dirs = ["etc/dbus-1/system.d/", "usr/share/dbus-1/system-services/"]
        
        for dbus_dir in dbus_dirs:
            files = self.handler.list_directory(dbus_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Check for suspicious Exec paths
                for line_num, line in enumerate(content.split('\n'), 1):
                    if 'Exec=' in line:
                        if any(p in line for p in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="dbus",
                                severity="HIGH",
                                description="D-Bus service with suspicious Exec path",
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # Polkit Rules
    # ========================================================================
    
    def _check_polkit(self) -> int:
        """Check Polkit rules for privilege escalation."""
        count = 0
        
        polkit_dirs = ["etc/polkit-1/rules.d/", "usr/share/polkit-1/rules.d/"]
        
        for polkit_dir in polkit_dirs:
            files = self.handler.list_directory(polkit_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Check for overly permissive rules
                if 'return polkit.Result.YES' in content:
                    self._add_finding(
                        filepath=filepath,
                        technique_key="polkit",
                        severity="HIGH",
                        description="Polkit rule with automatic approval",
                        indicator="polkit.Result.YES",
                        raw_content=content[:300]
                    )
                    count += 1
        
        return count
    
    # ========================================================================
    # Package Manager Hooks
    # ========================================================================
    
    def _check_package_hooks(self) -> int:
        """Check package manager hooks for persistence."""
        count = 0
        
        hook_dirs = [
            "etc/apt/apt.conf.d/",
            "etc/yum/pluginconf.d/",
            "etc/dnf/plugins/",
            "etc/dpkg/dpkg.cfg.d/",
        ]
        
        for hook_dir in hook_dirs:
            files = self.handler.list_directory(hook_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Check for suspicious pre/post hooks
                for line_num, line in enumerate(content.split('\n'), 1):
                    if any(hook in line.lower() for hook in ['pre-invoke', 'post-invoke', 'dpkg::pre', 'dpkg::post']):
                        if any(s in line for s in ['curl', 'wget', 'bash', '/tmp/', 'base64']):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="package_manager",
                                severity="HIGH",
                                description="Package manager hook with suspicious command",
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # GRUB Config
    # ========================================================================
    
    def _check_grub(self) -> int:
        """Check GRUB configuration for persistence."""
        count = 0
        
        grub_files = ["etc/default/grub", "boot/grub/grub.cfg", "boot/grub2/grub.cfg"]
        
        for grub_path in grub_files:
            data = self.handler.get_file(grub_path)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Check for suspicious init= or other kernel parameters
            for line_num, line in enumerate(content.split('\n'), 1):
                if 'init=' in line and '/bin/bash' in line:
                    self._add_finding(
                        filepath=grub_path,
                        technique_key="grub",
                        severity="CRITICAL",
                        description="GRUB config with init override to shell",
                        indicator="init=/bin/bash",
                        line_number=line_num,
                        raw_content=line[:200]
                    )
                    count += 1
        
        return count
    
    # ========================================================================
    # Initramfs
    # ========================================================================
    
    def _check_initramfs(self) -> int:
        """Check for initramfs backdoors."""
        count = 0
        
        # Look for initramfs hooks
        initramfs_dirs = ["etc/initramfs-tools/hooks/", "etc/initramfs-tools/scripts/"]
        
        for initramfs_dir in initramfs_dirs:
            files = self.handler.list_directory(initramfs_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                count += self._check_content_patterns(filepath, content,
                                                       SHELL_BACKDOOR_PATTERNS,
                                                       "initramfs")
        
        return count
    
    # ========================================================================
    # Additional Checks from Elastic Security Labs Series
    # ========================================================================
    
    def _check_systemd_generators(self) -> int:
        """
        Check systemd generators for persistence.
        
        Generators are executables run at boot to dynamically create unit files.
        Reference: https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms
        """
        count = 0
        
        for gen_dir in GENERATOR_PATHS:
            files = self.handler.list_directory(gen_dir)
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                # Any executable in generator directories is suspicious
                # unless it's a known system generator
                known_generators = [
                    'systemd-', 'getty-generator', 'fstab-generator',
                    'cryptsetup-generator', 'debug-generator'
                ]
                
                basename = os.path.basename(filepath)
                is_known = any(k in basename for k in known_generators)
                
                if not is_known:
                    self._add_finding(
                        filepath=filepath,
                        technique_key="generator",
                        severity="HIGH",
                        description=f"Custom systemd generator found",
                        indicator=basename,
                        extra_info={"size": len(data)}
                    )
                    count += 1
                
                # Check content for backdoors
                try:
                    content = data.decode('utf-8', errors='replace')
                    count += self._check_content_patterns(filepath, content,
                                                           SHELL_BACKDOOR_PATTERNS,
                                                           "generator")
                except Exception:
                    pass
        
        return count
    
    def _check_socket_activation(self) -> int:
        """
        Check systemd socket activation for persistence.
        
        Socket units can trigger services on network/file access.
        Reference: https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms
        """
        count = 0
        
        for socket_dir in SOCKET_PATHS:
            files = self.handler.list_directory(socket_dir)
            for filepath in files:
                if not filepath.endswith('.socket'):
                    continue
                
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Check for suspicious socket configurations
                for line_num, line in enumerate(content.split('\n'), 1):
                    line = line.strip()
                    
                    # ListenStream on unusual ports
                    if 'ListenStream=' in line:
                        port_match = re.search(r'ListenStream=(\d+)', line)
                        if port_match:
                            port = int(port_match.group(1))
                            # Common backdoor ports
                            if port in [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]:
                                self._add_finding(
                                    filepath=filepath,
                                    technique_key="socket_activation",
                                    severity="HIGH",
                                    description=f"Socket listening on suspicious port {port}",
                                    indicator=f"port={port}",
                                    line_number=line_num
                                )
                                count += 1
                    
                    # Accept=yes can be used for persistent connections
                    if 'Accept=yes' in line:
                        self._add_finding(
                            filepath=filepath,
                            technique_key="socket_activation",
                            severity="MEDIUM",
                            description="Socket with Accept=yes (connection forking)",
                            indicator="Accept=yes",
                            line_number=line_num
                        )
                        count += 1
        
        return count
    
    def _check_shadow_file(self) -> int:
        """
        Check /etc/shadow for suspicious entries.
        
        Reference: https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
        """
        count = 0
        
        shadow_data = self.handler.get_file("etc/shadow")
        if not shadow_data:
            return count
        
        try:
            content = shadow_data.decode('utf-8', errors='replace')
        except Exception:
            return count
        
        for line_num, line in enumerate(content.split('\n'), 1):
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(':')
            if len(parts) < 2:
                continue
            
            username = parts[0]
            password_hash = parts[1]
            
            # Check for empty password (no authentication required)
            if password_hash == '':
                self._add_finding(
                    filepath="etc/shadow",
                    technique_key="shadow",
                    severity="CRITICAL",
                    description=f"User '{username}' has empty password (no auth)",
                    indicator="empty_password",
                    line_number=line_num
                )
                count += 1
            
            # Check for simple/weak hashes (not $6$, $5$, $y$ formats)
            if password_hash and password_hash not in ['*', '!', '!!', '*LK*']:
                if not password_hash.startswith('$'):
                    self._add_finding(
                        filepath="etc/shadow",
                        technique_key="shadow",
                        severity="HIGH",
                        description=f"User '{username}' has weak/DES password hash",
                        indicator="weak_hash",
                        line_number=line_num
                    )
                    count += 1
        
        return count
    
    def _check_trap_commands(self) -> int:
        """
        Check for trap command persistence in shell scripts.
        
        trap can execute commands on signals/exit.
        Reference: https://www.elastic.co/security-labs/approaching-the-summit-on-persistence
        """
        count = 0
        
        trap_patterns = [
            (r"trap\s+['\"].*curl", "Trap with curl"),
            (r"trap\s+['\"].*wget", "Trap with wget"),
            (r"trap\s+['\"].*nc\s+", "Trap with netcat"),
            (r"trap\s+['\"].*bash\s+-", "Trap with bash"),
            (r"trap\s+['\"].*python", "Trap with python"),
            (r"trap\s+['\"].*base64", "Trap with base64"),
            (r"trap\s+.*EXIT", "Trap on EXIT"),
            (r"trap\s+.*ERR", "Trap on ERR"),
        ]
        
        # Check shell profile files
        profile_patterns = [
            r'\.bashrc$', r'\.bash_profile$', r'\.profile$',
            r'\.zshrc$', r'etc/profile$', r'etc/bash\.bashrc$'
        ]
        
        files = self.handler.find_files(profile_patterns)
        
        for filepath, member in files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            count += self._check_content_patterns(filepath, content,
                                                   trap_patterns,
                                                   "trap")
        
        return count
    
    def _check_message_queues(self) -> int:
        """
        Check for message queue persistence.
        
        POSIX message queues can be used for IPC-based persistence.
        Reference: https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence
        """
        count = 0
        
        # Check for mqueue mount
        mounts_data = self.handler.get_file("proc/mounts")
        if mounts_data:
            try:
                content = mounts_data.decode('utf-8', errors='replace')
                if 'mqueue' in content:
                    # Check dev/mqueue for suspicious queues
                    mqueue_files = self.handler.list_directory("dev/mqueue/")
                    for filepath in mqueue_files:
                        basename = os.path.basename(filepath)
                        # Hidden queue names or suspicious patterns
                        if basename.startswith('.') or any(s in basename.lower() for s in 
                            ['backdoor', 'shell', 'payload', 'cmd', 'exec']):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="message_queue",
                                severity="HIGH",
                                description=f"Suspicious message queue: {basename}",
                                indicator=basename
                            )
                            count += 1
            except Exception:
                pass
        
        return count
    
    def _check_ebpf(self) -> int:
        """
        Check for eBPF-based persistence.
        
        eBPF programs can intercept syscalls and network traffic.
        Reference: https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence
        """
        count = 0
        
        # Check for bpf filesystem
        bpf_dirs = ["sys/fs/bpf/", "sys/kernel/debug/tracing/"]
        
        for bpf_dir in bpf_dirs:
            files = self.handler.list_directory(bpf_dir)
            for filepath in files:
                # Look for suspicious program names
                basename = os.path.basename(filepath)
                suspicious_names = ['backdoor', 'rootkit', 'hide', 'stealth', 
                                   'intercept', 'hook', 'inject']
                
                if any(s in basename.lower() for s in suspicious_names):
                    self._add_finding(
                        filepath=filepath,
                        technique_key="rootkit",
                        severity="CRITICAL",
                        description=f"Suspicious eBPF program: {basename}",
                        indicator=basename
                    )
                    count += 1
        
        # Check for bpftool output if available
        bpf_output = self.handler.find_files([r'bpftool', r'bpf_progs'])
        for filepath, member in bpf_output:
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    if any(s in content.lower() for s in ['kprobe', 'tracepoint', 'xdp']):
                        self._add_finding(
                            filepath=filepath,
                            technique_key="rootkit",
                            severity="MEDIUM",
                            description="eBPF programs detected (review for legitimacy)",
                            raw_content=content[:300]
                        )
                        count += 1
                except Exception:
                    pass
        
        return count
    
    def _check_ld_cache(self) -> int:
        """
        Check dynamic linker cache for manipulation.
        
        ldconfig can be abused to inject malicious libraries.
        Reference: https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
        """
        count = 0
        
        # Check /etc/ld.so.cache modification (would need to compare against baseline)
        # For now, check related config files
        
        ld_conf_files = ["etc/ld.so.conf"] + self.handler.list_directory("etc/ld.so.conf.d/")
        
        suspicious_lib_paths = [
            '/tmp', '/var/tmp', '/dev/shm', '/home', '/root',
            '/.', '/usr/local/lib/.', '/opt/.'
        ]
        
        for filepath in ld_conf_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('include'):
                    continue
                
                # Check for suspicious paths
                for susp_path in suspicious_lib_paths:
                    if susp_path in line:
                        self._add_finding(
                            filepath=filepath,
                            technique_key="ld_preload",
                            severity="HIGH",
                            description=f"Suspicious library path in linker config",
                            indicator=line,
                            line_number=line_num
                        )
                        count += 1
                        break
        
        return count
    
    # ========================================================================
    # NEW: SSHD Config Analysis
    # ========================================================================
    
    def _check_sshd_config(self) -> int:
        """
        Check SSHD configuration for security issues.
        
        Looks for risky settings like PermitRootLogin, PasswordAuthentication,
        non-standard AuthorizedKeysFile locations, etc.
        """
        count = 0
        
        sshd_config_paths = [
            "etc/ssh/sshd_config",
            "etc/ssh/sshd_config.d/",
        ]
        
        for config_path in sshd_config_paths:
            if config_path.endswith('/'):
                files = self.handler.list_directory(config_path)
            else:
                files = [config_path]
            
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                for line_num, line in enumerate(content.split('\n'), 1):
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith('#'):
                        continue
                    
                    for pattern, description in SSHD_CONFIG_PATTERNS:
                        if re.search(pattern, line_stripped, re.IGNORECASE):
                            severity = "HIGH" if "Root" in description or "Empty" in description else "MEDIUM"
                            self._add_finding(
                                filepath=filepath,
                                technique_key="sshd_config",
                                severity=severity,
                                description=description,
                                indicator=line_stripped,
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # NEW: Environment Persistence
    # ========================================================================
    
    def _check_environment_persistence(self) -> int:
        """
        Check environment files for persistence mechanisms.
        
        Checks:
        - /etc/environment
        - /etc/security/pam_env.conf
        - /etc/security/pam_env.d/
        - LD_PRELOAD in /etc and /home
        """
        count = 0
        
        env_files = [
            "etc/environment",
            "etc/security/pam_env.conf",
        ]
        
        # Add pam_env.d files
        env_files.extend(self.handler.list_directory("etc/security/pam_env.d/"))
        
        for filepath in env_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                
                for pattern, description in ENVIRONMENT_PERSISTENCE_PATTERNS:
                    if re.search(pattern, line_stripped, re.IGNORECASE):
                        severity = "HIGH" if "LD_PRELOAD" in description else "MEDIUM"
                        self._add_finding(
                            filepath=filepath,
                            technique_key="environment_persistence",
                            severity=severity,
                            description=description,
                            indicator=line_stripped[:100],
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        # Search for LD_PRELOAD in etc and home directories
        search_patterns = [r'etc/.*', r'home/.*']
        files = self.handler.find_files(search_patterns)
        
        for filepath, member in files:
            # Skip binary files and large files
            if hasattr(member, 'size') and member.size > 1024 * 1024:  # 1MB limit
                continue
            
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Search for LD_PRELOAD
            for line_num, line in enumerate(content.split('\n'), 1):
                if 'LD_PRELOAD' in line:
                    self._add_finding(
                        filepath=filepath,
                        technique_key="ld_preload",
                        severity="HIGH",
                        description="LD_PRELOAD reference found",
                        indicator=line[:100].strip(),
                        line_number=line_num,
                        raw_content=line[:200]
                    )
                    count += 1
        
        return count
    
    # ========================================================================
    # NEW: Docker Persistence
    # ========================================================================
    
    def _check_docker_persistence(self) -> int:
        """
        Comprehensive Docker analysis - extracts ALL Docker information.
        
        Checks for:
        - Docker installation (binaries, service files)
        - Docker daemon configuration
        - All containers (running and stopped)
        - Container configurations (mounts, privileges, networks)
        - Docker images
        - Docker volumes
        - Docker networks
        - Docker Compose files
        - Dockerfiles
        - Docker socket permissions
        - Suspicious persistence patterns
        """
        count = 0
        docker_installed = False
        
        # ================================================================
        # 1. Check if Docker is installed
        # ================================================================
        docker_binaries = [
            "usr/bin/docker",
            "usr/local/bin/docker",
            "usr/bin/dockerd",
            "usr/bin/containerd",
        ]
        
        for binary_path in docker_binaries:
            data = self.handler.get_file(binary_path)
            if data:
                docker_installed = True
                self._add_finding(
                    filepath=binary_path,
                    technique_key="docker_persistence",
                    severity="INFO",
                    description="Docker binary found - Docker is installed",
                    indicator=binary_path
                )
                count += 1
                break
        
        # Check for Docker service
        docker_service_paths = [
            "etc/systemd/system/docker.service",
            "usr/lib/systemd/system/docker.service",
            "lib/systemd/system/docker.service",
        ]
        
        for service_path in docker_service_paths:
            data = self.handler.get_file(service_path)
            if data:
                docker_installed = True
                self._add_finding(
                    filepath=service_path,
                    technique_key="docker_persistence",
                    severity="INFO",
                    description="Docker systemd service found",
                    indicator="Docker service is configured",
                    raw_content=data.decode('utf-8', errors='replace')[:500]
                )
                count += 1
                break
        
        if not docker_installed:
            # Check var/lib/docker existence as final check
            docker_lib_files = self.handler.list_directory("var/lib/docker/")
            if docker_lib_files:
                docker_installed = True
        
        if not docker_installed:
            self._add_finding(
                filepath="",
                technique_key="docker_persistence",
                severity="INFO",
                description="Docker does not appear to be installed on this system",
                indicator="No Docker binaries, services, or data directories found"
            )
            return 1
        
        # ================================================================
        # 2. Docker Daemon Configuration
        # ================================================================
        daemon_config_paths = [
            "etc/docker/daemon.json",
            "root/.docker/daemon.json",
        ]
        
        for config_path in daemon_config_paths:
            data = self.handler.get_file(config_path)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    self._add_finding(
                        filepath=config_path,
                        technique_key="docker_persistence",
                        severity="INFO",
                        description="Docker daemon configuration",
                        indicator="Docker daemon.json found",
                        raw_content=content[:1000]
                    )
                    count += 1
                    
                    # Check for insecure configurations
                    if '"insecure-registries"' in content:
                        self._add_finding(
                            filepath=config_path,
                            technique_key="docker_persistence",
                            severity="MEDIUM",
                            description="Docker configured with insecure registries",
                            indicator="insecure-registries configured",
                            raw_content=content[:500]
                        )
                        count += 1
                    
                    if '"live-restore"' in content and 'false' in content.lower():
                        self._add_finding(
                            filepath=config_path,
                            technique_key="docker_persistence",
                            severity="LOW",
                            description="Docker live-restore disabled",
                            indicator="live-restore: false"
                        )
                        count += 1
                except Exception:
                    pass
        
        # ================================================================
        # 3. Enumerate All Containers
        # ================================================================
        containers_path = "var/lib/docker/containers/"
        container_dirs = self.handler.list_directory(containers_path)
        
        container_count = 0
        for container_dir in container_dirs:
            if not container_dir or container_dir == containers_path:
                continue
            
            # Get container config
            config_path = f"{container_dir}/config.v2.json" if not container_dir.endswith('/') else f"{container_dir}config.v2.json"
            config_data = self.handler.get_file(config_path)
            
            if config_data:
                container_count += 1
                try:
                    content = config_data.decode('utf-8', errors='replace')
                    
                    # Extract container info
                    container_id = os.path.basename(container_dir.rstrip('/'))[:12]
                    
                    # Try to parse JSON for details
                    import json
                    try:
                        config = json.loads(content)
                        container_name = config.get('Name', '').lstrip('/')
                        image = config.get('Config', {}).get('Image', 'unknown')
                        state = config.get('State', {})
                        running = state.get('Running', False)
                        
                        status = "RUNNING" if running else "STOPPED"
                        
                        self._add_finding(
                            filepath=config_path,
                            technique_key="docker_persistence",
                            severity="INFO",
                            description=f"Docker Container: {container_name} ({status})",
                            indicator=f"ID: {container_id}, Image: {image}",
                            raw_content=f"Name: {container_name}\nImage: {image}\nStatus: {status}\nID: {container_id}"
                        )
                        count += 1
                        
                        # Check for privileged mode
                        host_config = config.get('HostConfig', {})
                        if host_config.get('Privileged', False):
                            self._add_finding(
                                filepath=config_path,
                                technique_key="docker_persistence",
                                severity="CRITICAL",
                                description=f"PRIVILEGED Container: {container_name}",
                                indicator="Container runs in privileged mode - full host access",
                                raw_content=f"Container {container_name} has privileged=true"
                            )
                            count += 1
                        
                        # Check for dangerous mounts
                        binds = host_config.get('Binds', []) or []
                        for bind in binds:
                            if isinstance(bind, str):
                                # Check for dangerous mounts
                                dangerous_mounts = [
                                    ('/:/host', 'Root filesystem mounted'),
                                    ('/etc:', '/etc mounted'),
                                    ('/root:', '/root mounted'),
                                    ('/var/run/docker.sock', 'Docker socket mounted'),
                                    ('/proc:', '/proc mounted'),
                                    ('/sys:', '/sys mounted'),
                                ]
                                
                                for pattern, desc in dangerous_mounts:
                                    if pattern in bind:
                                        self._add_finding(
                                            filepath=config_path,
                                            technique_key="docker_persistence",
                                            severity="HIGH" if 'socket' in pattern else "MEDIUM",
                                            description=f"Container mount: {desc}",
                                            indicator=f"Container: {container_name}, Mount: {bind}",
                                            raw_content=bind
                                        )
                                        count += 1
                        
                        # Check for host network mode
                        if host_config.get('NetworkMode') == 'host':
                            self._add_finding(
                                filepath=config_path,
                                technique_key="docker_persistence",
                                severity="MEDIUM",
                                description=f"Container using host network: {container_name}",
                                indicator="NetworkMode: host",
                                raw_content=f"Container {container_name} uses host network namespace"
                            )
                            count += 1
                        
                        # Check for host PID namespace
                        if host_config.get('PidMode') == 'host':
                            self._add_finding(
                                filepath=config_path,
                                technique_key="docker_persistence",
                                severity="HIGH",
                                description=f"Container using host PID namespace: {container_name}",
                                indicator="PidMode: host",
                                raw_content=f"Container {container_name} can see host processes"
                            )
                            count += 1
                        
                        # Check for added capabilities
                        cap_add = host_config.get('CapAdd', []) or []
                        if cap_add:
                            for cap in cap_add:
                                severity = "HIGH" if cap in ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN'] else "MEDIUM"
                                self._add_finding(
                                    filepath=config_path,
                                    technique_key="docker_persistence",
                                    severity=severity,
                                    description=f"Container with added capability: {cap}",
                                    indicator=f"Container: {container_name}, Capability: {cap}",
                                    raw_content=f"CapAdd: {cap_add}"
                                )
                                count += 1
                        
                    except json.JSONDecodeError:
                        # Couldn't parse JSON, just log the container
                        self._add_finding(
                            filepath=config_path,
                            technique_key="docker_persistence",
                            severity="INFO",
                            description=f"Docker Container found (ID: {container_id})",
                            indicator=container_id,
                            raw_content=content[:500]
                        )
                        count += 1
                except Exception:
                    pass
        
        if container_count > 0:
            self._add_finding(
                filepath=containers_path,
                technique_key="docker_persistence",
                severity="INFO",
                description=f"Total Docker containers found: {container_count}",
                indicator=f"{container_count} containers"
            )
            count += 1
        
        # ================================================================
        # 4. Docker Images (from image database)
        # ================================================================
        image_db_path = "var/lib/docker/image/overlay2/repositories.json"
        image_data = self.handler.get_file(image_db_path)
        
        if image_data:
            try:
                content = image_data.decode('utf-8', errors='replace')
                import json
                repos = json.loads(content)
                
                repositories = repos.get('Repositories', {})
                image_list = []
                for repo_name, tags in repositories.items():
                    for tag, image_id in tags.items():
                        image_list.append(f"{repo_name}:{tag}")
                
                if image_list:
                    self._add_finding(
                        filepath=image_db_path,
                        technique_key="docker_persistence",
                        severity="INFO",
                        description=f"Docker Images ({len(image_list)} found)",
                        indicator=", ".join(image_list[:10]) + ("..." if len(image_list) > 10 else ""),
                        raw_content="\n".join(image_list)
                    )
                    count += 1
            except Exception:
                pass
        
        # ================================================================
        # 5. Docker Volumes
        # ================================================================
        volumes_path = "var/lib/docker/volumes/"
        volume_dirs = self.handler.list_directory(volumes_path)
        
        volume_names = []
        for vol_dir in volume_dirs:
            if vol_dir and vol_dir != volumes_path and 'metadata.db' not in vol_dir:
                vol_name = os.path.basename(vol_dir.rstrip('/'))
                if vol_name and vol_name != 'backingFsBlockDev':
                    volume_names.append(vol_name)
        
        if volume_names:
            self._add_finding(
                filepath=volumes_path,
                technique_key="docker_persistence",
                severity="INFO",
                description=f"Docker Volumes ({len(volume_names)} found)",
                indicator=", ".join(volume_names[:10]) + ("..." if len(volume_names) > 10 else ""),
                raw_content="\n".join(volume_names)
            )
            count += 1
        
        # ================================================================
        # 6. Docker Networks
        # ================================================================
        networks_path = "var/lib/docker/network/files/local-kv.db"
        network_data = self.handler.get_file(networks_path)
        
        if network_data:
            self._add_finding(
                filepath=networks_path,
                technique_key="docker_persistence",
                severity="INFO",
                description="Docker network database found",
                indicator="Docker custom networks may be configured"
            )
            count += 1
        
        # ================================================================
        # 7. Docker Compose Files
        # ================================================================
        compose_patterns = [r'docker-compose\.ya?ml$', r'compose\.ya?ml$']
        compose_files = self.handler.find_files(compose_patterns)
        
        for filepath, member in compose_files:
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    self._add_finding(
                        filepath=filepath,
                        technique_key="docker_persistence",
                        severity="INFO",
                        description="Docker Compose file found",
                        indicator=filepath,
                        raw_content=content[:1500]
                    )
                    count += 1
                    
                    # Check for privileged in compose
                    if 'privileged: true' in content or 'privileged:true' in content:
                        self._add_finding(
                            filepath=filepath,
                            technique_key="docker_persistence",
                            severity="CRITICAL",
                            description="Docker Compose with privileged container",
                            indicator="privileged: true in compose file",
                            raw_content=content[:500]
                        )
                        count += 1
                except Exception:
                    pass
        
        # ================================================================
        # 8. Dockerfiles
        # ================================================================
        dockerfile_patterns = [r'Dockerfile$', r'Dockerfile\.[a-zA-Z]+$']
        dockerfiles = self.handler.find_files(dockerfile_patterns)
        
        for filepath, member in dockerfiles:
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    
                    # Extract base image
                    base_image = "unknown"
                    for line in content.split('\n'):
                        if line.strip().upper().startswith('FROM '):
                            base_image = line.strip()[5:].strip()
                            break
                    
                    self._add_finding(
                        filepath=filepath,
                        technique_key="docker_persistence",
                        severity="INFO",
                        description=f"Dockerfile found (base: {base_image})",
                        indicator=f"Base image: {base_image}",
                        raw_content=content[:1000]
                    )
                    count += 1
                except Exception:
                    pass
        
        # ================================================================
        # 9. Docker Socket Permissions
        # ================================================================
        socket_path = "var/run/docker.sock"
        # Can't check permissions in tarball easily, but check if it exists
        
        # Check for users in docker group
        group_data = self.handler.get_file("etc/group")
        if group_data:
            try:
                content = group_data.decode('utf-8', errors='replace')
                for line in content.split('\n'):
                    if line.startswith('docker:'):
                        parts = line.split(':')
                        if len(parts) >= 4 and parts[3]:
                            docker_users = parts[3]
                            self._add_finding(
                                filepath="etc/group",
                                technique_key="docker_persistence",
                                severity="INFO",
                                description="Users in docker group (can run containers)",
                                indicator=f"Docker group members: {docker_users}",
                                raw_content=line
                            )
                            count += 1
                        break
            except Exception:
                pass
        
        return count
    
    # ========================================================================
    # NEW: Modprobe and Kernel Modules Configuration
    # ========================================================================
    
    def _check_modprobe_modules(self) -> int:
        """
        Check kernel module loading configurations.
        
        Checks:
        - /etc/modprobe.d/
        - /etc/modules-load.d/
        - /etc/modules
        """
        count = 0
        
        module_paths = [
            "etc/modprobe.d/",
            "etc/modules-load.d/",
            "etc/modules",
        ]
        
        # Known suspicious modules
        suspicious_modules = [
            'diamorphine', 'reptile', 'jynx', 'azazel', 'suterusu',
            'adore', 'phalanx', 'brootus', 'bdvl', 'beurk', 'knark',
            'modhide', 'enyelkm', 'override'
        ]
        
        # Suspicious modprobe options
        suspicious_options = [
            (r'install\s+\S+\s+/bin/', "Module install script with /bin/"),
            (r'install\s+\S+\s+.*curl', "Module install with curl"),
            (r'install\s+\S+\s+.*wget', "Module install with wget"),
            (r'install\s+\S+\s+.*bash', "Module install with bash"),
            (r'install\s+\S+\s+.*python', "Module install with python"),
            (r'softdep\s+\S+\s+pre:', "Module soft dependency (pre)"),
        ]
        
        for module_path in module_paths:
            if module_path.endswith('/'):
                files = self.handler.list_directory(module_path)
            else:
                files = [module_path]
            
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                for line_num, line in enumerate(content.split('\n'), 1):
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith('#'):
                        continue
                    
                    # Check for suspicious modules
                    for susp_mod in suspicious_modules:
                        if susp_mod in line_stripped.lower():
                            self._add_finding(
                                filepath=filepath,
                                technique_key="modprobe",
                                severity="CRITICAL",
                                description=f"Suspicious kernel module: {susp_mod}",
                                indicator=line_stripped[:100],
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
                    
                    # Check for suspicious options
                    for pattern, description in suspicious_options:
                        if re.search(pattern, line_stripped, re.IGNORECASE):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="modprobe",
                                severity="HIGH",
                                description=description,
                                indicator=line_stripped[:100],
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # NEW: Dracut Persistence
    # ========================================================================
    
    def _check_dracut(self) -> int:
        """
        Check Dracut modules for persistence.
        
        Checks:
        - /usr/lib/dracut/modules.d/
        - /lib/dracut/modules.d/
        """
        count = 0
        
        dracut_paths = [
            "usr/lib/dracut/modules.d/",
            "lib/dracut/modules.d/",
            "etc/dracut.conf.d/",
        ]
        
        suspicious_patterns = [
            (r'curl\s+', "Curl in dracut module"),
            (r'wget\s+', "Wget in dracut module"),
            (r'nc\s+-', "Netcat in dracut module"),
            (r'/dev/tcp/', "/dev/tcp in dracut module"),
            (r'base64.*\|', "Base64 pipe in dracut module"),
            (r'bash\s+-i', "Interactive bash in dracut module"),
            (r'python.*-c', "Python -c in dracut module"),
        ]
        
        for dracut_path in dracut_paths:
            files = self.handler.list_directory(dracut_path)
            
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Report existence of custom dracut modules (could be legitimate)
                if 'module-setup.sh' in filepath:
                    self._add_finding(
                        filepath=filepath,
                        technique_key="dracut",
                        severity="INFO",
                        description="Custom dracut module found",
                        indicator=os.path.basename(os.path.dirname(filepath))
                    )
                    count += 1
                
                # Check for suspicious content
                for line_num, line in enumerate(content.split('\n'), 1):
                    for pattern, description in suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self._add_finding(
                                filepath=filepath,
                                technique_key="dracut",
                                severity="HIGH",
                                description=description,
                                indicator=line[:100].strip(),
                                line_number=line_num,
                                raw_content=line[:200]
                            )
                            count += 1
        
        return count
    
    # ========================================================================
    # NEW: Sketchy Code Detection
    # ========================================================================
    
    def _check_sketchy_code(self) -> int:
        """
        Scan for sketchy/suspicious code patterns across all files.
        
        Looks for network tools, shell invocations, obfuscation, etc.
        """
        count = 0
        
        # File extensions to scan
        code_patterns = [
            r'\.sh$', r'\.bash$', r'\.py$', r'\.pl$', r'\.rb$',
            r'\.php$', r'\.js$', r'\.ts$', r'\.go$', r'\.c$', r'\.h$',
            r'Makefile$', r'\.mk$', r'\.yml$', r'\.yaml$', r'\.conf$',
        ]
        
        files = self.handler.find_files(code_patterns)
        
        all_patterns = SKETCHY_CODE_PATTERNS + REVERSE_SHELL_PATTERNS
        
        for filepath, member in files:
            # Skip large files
            if hasattr(member, 'size') and member.size > 500 * 1024:  # 500KB limit
                continue
            
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern, description in all_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Determine severity based on pattern type
                        if any(x in description.lower() for x in ['reverse', 'shell', 'netcat', '/dev/tcp']):
                            severity = "CRITICAL"
                        elif any(x in description.lower() for x in ['curl', 'wget', 'base64', 'eval']):
                            severity = "HIGH"
                        else:
                            severity = "MEDIUM"
                        
                        self._add_finding(
                            filepath=filepath,
                            technique_key="sketchy_code",
                            severity=severity,
                            description=description,
                            indicator=line[:100].strip(),
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
                        break  # One finding per line max
        
        return count
    
    # ========================================================================
    # NEW: NPM Backdoors
    # ========================================================================
    
    def _check_npm_backdoors(self) -> int:
        """
        Check NPM package.json files for backdoor patterns.
        
        Looks for suspicious postinstall/preinstall scripts.
        """
        count = 0
        
        package_files = self.handler.find_files([r'package\.json$'])
        
        for filepath, member in package_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern, description in NPM_BACKDOOR_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # postinstall itself is INFO, but with suspicious commands is HIGH
                        if any(x in line.lower() for x in ['curl', 'wget', 'bash', 'sh ', 'nc ', 'python']):
                            severity = "HIGH"
                        elif 'postinstall' in line or 'preinstall' in line:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                        
                        self._add_finding(
                            filepath=filepath,
                            technique_key="npm_backdoor",
                            severity=severity,
                            description=description,
                            indicator=line[:100].strip(),
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # NEW: Python Backdoors
    # ========================================================================
    
    def _check_python_backdoors(self) -> int:
        """
        Check Python files for backdoor patterns.
        
        Looks for:
        - setup.py with suspicious hooks
        - sitecustomize.py / usercustomize.py
        - urllib/requests/socket usage in unexpected places
        """
        count = 0
        
        # Check setup.py files
        setup_files = self.handler.find_files([r'setup\.py$'])
        
        for filepath, member in setup_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Check for suspicious patterns
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern, description in PYTHON_BACKDOOR_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # cmdclass is more suspicious
                        severity = "MEDIUM" if 'cmdclass' in line.lower() else "LOW"
                        self._add_finding(
                            filepath=filepath,
                            technique_key="python_backdoor",
                            severity=severity,
                            description=description,
                            indicator=line[:100].strip(),
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        # Check for sitecustomize.py and usercustomize.py
        site_patterns = [r'sitecustomize\.py$', r'usercustomize\.py$']
        site_files = self.handler.find_files(site_patterns)
        
        for filepath, member in site_files:
            self._add_finding(
                filepath=filepath,
                technique_key="python_backdoor",
                severity="HIGH",
                description="Python site customization file found",
                indicator=os.path.basename(filepath)
            )
            count += 1
            
            # Check content for suspicious patterns
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    for line_num, line in enumerate(content.split('\n'), 1):
                        for pattern, description in SKETCHY_CODE_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                self._add_finding(
                                    filepath=filepath,
                                    technique_key="python_backdoor",
                                    severity="CRITICAL",
                                    description=f"Site customize with: {description}",
                                    indicator=line[:100].strip(),
                                    line_number=line_num,
                                    raw_content=line[:200]
                                )
                                count += 1
                except Exception:
                    pass
        
        return count
    
    # ========================================================================
    # NEW: Makefile Backdoors
    # ========================================================================
    
    def _check_makefiles(self) -> int:
        """
        Check Makefiles for backdoor patterns.
        
        Looks for curl, wget, python, netcat, bash in make recipes.
        """
        count = 0
        
        makefile_patterns = [r'Makefile$', r'makefile$', r'\.mk$', r'GNUmakefile$']
        makefile_files = self.handler.find_files(makefile_patterns)
        
        for filepath, member in makefile_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern, description in MAKEFILE_BACKDOOR_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self._add_finding(
                            filepath=filepath,
                            technique_key="makefile_backdoor",
                            severity="MEDIUM",
                            description=description,
                            indicator=line[:100].strip(),
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # NEW: IP Connection Patterns
    # ========================================================================
    
    def _check_ip_connections(self) -> int:
        """
        Search for hardcoded IP:port patterns and /dev/tcp connections.
        
        This can reveal C2 server addresses or backdoor connections.
        """
        count = 0
        
        # Search all text-like files
        text_patterns = [
            r'\.sh$', r'\.bash$', r'\.py$', r'\.pl$', r'\.rb$',
            r'\.php$', r'\.js$', r'\.conf$', r'\.cfg$', r'\.ini$',
            r'\.yml$', r'\.yaml$', r'\.json$', r'\.xml$',
            r'crontab$', r'rc\.local$', r'\.bashrc$', r'\.profile$',
        ]
        
        files = self.handler.find_files(text_patterns)
        
        # Combined IP patterns
        ip_patterns = IP_CONNECTION_PATTERNS + [
            (r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{2,5}\b', "IP:port connection"),
        ]
        
        # Known safe/internal IPs to skip (configurable)
        safe_ips = {'127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'}
        
        for filepath, member in files:
            if hasattr(member, 'size') and member.size > 500 * 1024:
                continue
            
            data = self.handler.get_file(filepath)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern, description in ip_patterns:
                    match = re.search(pattern, line)
                    if match:
                        matched_text = match.group(0)
                        
                        # Skip safe IPs
                        is_safe = any(matched_text.startswith(safe) for safe in safe_ips)
                        if is_safe:
                            continue
                        
                        # /dev/tcp is always suspicious
                        if '/dev/tcp' in matched_text:
                            severity = "CRITICAL"
                        else:
                            severity = "HIGH"
                        
                        self._add_finding(
                            filepath=filepath,
                            technique_key="ip_connection",
                            severity=severity,
                            description=description,
                            indicator=matched_text,
                            line_number=line_num,
                            raw_content=line[:200]
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # NEW: Active Git Hooks (non-sample)
    # ========================================================================
    
    def _check_git_hooks_active(self) -> int:
        """
        Find active (non-sample) git hooks that could be malicious.
        
        Searches for git hooks that are not .sample files.
        """
        count = 0
        
        # Find all .git/hooks directories
        git_hook_patterns = [r'\.git/hooks/']
        
        # Get all files in git hooks directories
        hook_files = self.handler.find_files([r'\.git/hooks/[^/]+$'])
        
        for filepath, member in hook_files:
            # Skip sample files
            if filepath.endswith('.sample'):
                continue
            
            basename = os.path.basename(filepath)
            
            # Common hook names
            hook_names = ['pre-commit', 'post-commit', 'pre-push', 'post-receive',
                         'pre-receive', 'update', 'post-update', 'pre-rebase',
                         'post-checkout', 'post-merge', 'pre-auto-gc', 'commit-msg',
                         'prepare-commit-msg', 'applypatch-msg', 'post-applypatch']
            
            if basename in hook_names:
                self._add_finding(
                    filepath=filepath,
                    technique_key="git_hook_active",
                    severity="MEDIUM",
                    description=f"Active git hook: {basename}",
                    indicator=basename
                )
                count += 1
                
                # Check content for suspicious patterns
                data = self.handler.get_file(filepath)
                if data:
                    try:
                        content = data.decode('utf-8', errors='replace')
                        for line_num, line in enumerate(content.split('\n'), 1):
                            for pattern, description in SKETCHY_CODE_PATTERNS + REVERSE_SHELL_PATTERNS:
                                if re.search(pattern, line, re.IGNORECASE):
                                    self._add_finding(
                                        filepath=filepath,
                                        technique_key="git_hook_active",
                                        severity="HIGH",
                                        description=f"Git hook with: {description}",
                                        indicator=line[:100].strip(),
                                        line_number=line_num,
                                        raw_content=line[:200]
                                    )
                                    count += 1
                    except Exception:
                        pass
        
        return count
    
    # ========================================================================
    # Summary and Export
    # ========================================================================
    
    def _print_summary(self) -> None:
        """Print detection summary."""
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Detection Summary{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1
        
        print(f"\n{Style.INFO}Findings by Severity:{Style.RESET}", file=sys.stderr)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = {
                    "CRITICAL": Style.CRITICAL,
                    "HIGH": Style.ERROR,
                    "MEDIUM": Style.WARNING,
                    "LOW": Style.INFO,
                    "INFO": Style.DIM
                }.get(severity, Style.RESET)
                print(f"  {color}{severity}: {count}{Style.RESET}", file=sys.stderr)
        
        print(f"\n{Style.INFO}Findings by Technique:{Style.RESET}", file=sys.stderr)
        for tech, count in sorted(self.stats.items()):
            technique_name, mitre_id = MITRE_MAPPINGS.get(tech, (tech, "N/A"))
            print(f"  {technique_name} ({mitre_id}): {count}", file=sys.stderr)
        
        print(f"\n{Style.SUCCESS}Total Findings: {len(self.findings)}{Style.RESET}", file=sys.stderr)
    
    def _get_hostname(self) -> str:
        """Try to determine hostname from the source."""
        # Try to read etc/hostname
        hostname_data = self.handler.get_file("etc/hostname")
        if hostname_data:
            try:
                hostname = hostname_data.decode('utf-8', errors='replace').strip().split('\n')[0]
                if hostname and len(hostname) < 64:
                    return hostname
            except Exception:
                pass
        
        # Fallback to source directory/file name
        source_name = os.path.basename(self.source_path.rstrip('/\\'))
        if source_name and source_name != '.' and source_name != '/':
            # Remove common extensions
            for ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar'):
                if source_name.lower().endswith(ext):
                    source_name = source_name[:-len(ext)]
                    break
            return source_name
        
        return "unknown"
    
    def export_csv(self, output_path: str) -> None:
        """Export findings to CSV."""
        if not self.findings:
            print(f"{Style.INFO}No findings to export{Style.RESET}", file=sys.stderr)
            return
        
        # If output_path is a directory, create a filename inside it
        if os.path.isdir(output_path):
            hostname = self._get_hostname()
            filename = f"{hostname}_persistence_findings.csv"
            output_path = os.path.join(output_path, filename)
        
        # Ensure parent directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ["Filepath", "Technique", "MITRE_ATT&CK_ID", "Severity",
                         "Description", "Indicator", "Line_Number", "Raw_Content",
                         "MD5", "SHA256", "File_Mode", "Extra_Info"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Sort by severity, then technique
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            
            for finding in sorted(self.findings, key=lambda x: (
                severity_order.get(x.severity, 5),
                x.technique,
                x.filepath
            )):
                writer.writerow(finding.to_dict())
        
        print(f"{Style.SUCCESS}Findings exported to:{Style.RESET} {output_path}", file=sys.stderr)


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Detect Linux persistence mechanisms (PANIX-style)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

This tool detects persistence mechanisms used by attackers, including all
techniques implemented by PANIX (https://github.com/Aegrah/PANIX).

Supported Input Types (-s/--source):
  • UAC tarball:        .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz
  • Extracted directory: Any directory containing Linux filesystem artifacts
  • Live system:        Use "/" with root privileges

Output (-o):
  • File path:          Write directly to specified CSV file
  • Directory path:     Auto-generates [hostname]_persistence_findings.csv

Examples:
  # Hunt for persistence in a UAC tarball
  python linux_persistence_hunter.py -s uac-hostname.tar.gz -o findings.csv
  
  # Hunt in extracted directory, output to current dir
  python linux_persistence_hunter.py -s ./extracted_uac/ -o .
  
  # Hunt on live system (requires root)
  sudo python linux_persistence_hunter.py -s / -o /tmp/findings.csv

Detected Techniques (mapped to MITRE ATT&CK):
  - Scheduled Tasks: Cron (T1053.003), At (T1053.002), Systemd Timers
  - Account Manipulation: SSH Keys (T1098.004), Backdoor Users (T1136.001)
  - Boot/Logon: init.d, rc.local (T1037.004), MOTD, XDG Autostart
  - System Services: Systemd (T1543.002), D-Bus
  - Hijack Execution: LD_PRELOAD (T1574.006), Capabilities, SUID (T1548.001)
  - Shell Config: .bashrc/.profile (T1546.004)
  - Auth Modification: PAM (T1556.003), Sudoers (T1548.003), Polkit
  - Event Triggered: Udev (T1546.017), Git Hooks, Package Hooks
  - Rootkits: LKM (T1547.006), LD.so.preload
  - Web Shells (T1505.003)
  - Container Escape (T1610)
  
NEW Extended Checks:
  - SSHD Config: PermitRootLogin, AuthorizedKeysFile, etc. (T1021.004)
  - Environment Persistence: /etc/environment, pam_env.conf (T1546.004)
  - Docker Persistence: Bind mounts, privileged containers (T1609)
  - Kernel Modules: modprobe.d, modules-load.d (T1547.006)
  - Dracut Modules: initramfs persistence (T1542)
  - Sketchy Code: curl|wget|nc|bash -i|/dev/tcp patterns (T1059)
  - NPM Backdoors: postinstall/preinstall hooks (T1195.001)
  - Python Backdoors: setup.py, sitecustomize.py (T1195.001)
  - Makefile Backdoors: curl/wget/bash in makefiles (T1195)
  - IP Connections: Hardcoded IP:port patterns (T1046)
  - Active Git Hooks: Non-sample git hooks (T1546)

Reference: https://github.com/Aegrah/PANIX
        """
    )
    
    parser.add_argument(
        "-s", "--source",
        default="/",
        help="Source path: UAC tarball, extracted directory, or '/' for live system"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="persistence_findings.csv",
        help="Output CSV file (default: persistence_findings.csv)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output"
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    args = parser.parse_args()
    
    # Resolve source path
    source_path = args.source
    if source_path != "/" and not os.path.isabs(source_path):
        source_path = os.path.abspath(source_path)
    
    if not os.path.exists(source_path):
        print(f"{Style.ERROR}Error: Source path does not exist: {source_path}{Style.RESET}", file=sys.stderr)
        sys.exit(1)
    
    try:
        hunter = PersistenceHunter(source_path)
        hunter.hunt(verbose=not args.quiet)
        
        output_path = args.output
        if not os.path.isabs(output_path):
            output_path = os.path.abspath(output_path)
        
        hunter.export_csv(output_path)
        hunter.close()
        
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Hunt interrupted by user{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

