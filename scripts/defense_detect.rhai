// @name: defense_detect
// @description: Detect security tools, AV/EDR, monitoring, and defenses
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Defense & Security Tool Detection ===\n";
let defenses_found = 0;

// --- AV / EDR processes ---
output += "\n\x1b[1;4mAV / EDR / Agent Processes:\x1b[0m\n";
let av_edr_patterns = [
    "clamd", "freshclam",
    "falcon-sensor", "falconctl",
    "cbagent", "cbdaemon", "cbsensor",
    "ossec", "wazuh",
    "sentinelone", "sentinelagent",
    "cylancesvc",
    "elastic-agent", "filebeat", "metricbeat",
    "datadog", "dd-agent",
    "newrelic",
    "qualys", "nessus",
    "sophos", "savscand",
    "clamav",
    "rkhunter", "chkrootkit",
];

let all_procs = exec_cmd("ps aux 2>/dev/null");
for pattern in av_edr_patterns {
    if all_procs.contains(pattern) {
        output += "  \x1b[1;31m[!] " + pattern + " detected!\x1b[0m\n";
        defenses_found += 1;
    }
}

// Check /opt and /usr/local for common agent directories
let agent_dirs = exec_cmd("ls -d /opt/CrowdStrike /opt/carbonblack /opt/SentinelOne /opt/qualys /opt/nessus /opt/sophos /opt/McAfee /opt/rapid7 /opt/tanium /opt/splunkforwarder /opt/elastic-agent 2>/dev/null");
if agent_dirs.len() > 0 {
    for line in agent_dirs.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[1;31m[!] Agent directory: " + line + "\x1b[0m\n";
            defenses_found += 1;
        }
    }
}

if defenses_found == 0 {
    output += "  (no AV/EDR agents detected)\n";
}

// --- SELinux ---
output += "\n\x1b[1;4mSELinux:\x1b[0m\n";
let selinux = exec_cmd("getenforce 2>/dev/null");
let sestatus = exec_cmd("sestatus 2>/dev/null");
if selinux.len() > 0 {
    if selinux.contains("Enforcing") {
        output += "  \x1b[1;31mSELinux: ENFORCING\x1b[0m\n";
        defenses_found += 1;
    } else if selinux.contains("Permissive") {
        output += "  \x1b[33mSELinux: Permissive (logging only)\x1b[0m\n";
    } else {
        output += "  SELinux: " + selinux.trim() + "\n";
    }
    if sestatus.len() > 0 {
        for line in sestatus.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
} else {
    output += "  (not available)\n";
}

// --- AppArmor ---
output += "\n\x1b[1;4mAppArmor:\x1b[0m\n";
let apparmor = exec_cmd("aa-status 2>/dev/null || cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -20");
if apparmor.len() > 0 {
    output += "  \x1b[33mAppArmor active\x1b[0m\n";
    for line in apparmor.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    defenses_found += 1;
} else {
    output += "  (not available)\n";
}

// --- Audit ---
output += "\n\x1b[1;4mAudit Framework:\x1b[0m\n";
let auditd = exec_cmd("systemctl is-active auditd 2>/dev/null");
let audit_rules = exec_cmd("auditctl -l 2>/dev/null | head -20");
if auditd.contains("active") {
    output += "  \x1b[1;31mauditd is ACTIVE\x1b[0m\n";
    defenses_found += 1;
    if audit_rules.len() > 0 && !audit_rules.contains("No rules") {
        output += "  Audit rules:\n";
        for line in audit_rules.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
} else {
    output += "  auditd: " + auditd.trim() + "\n";
}

// --- Logging ---
output += "\n\x1b[1;4mLogging:\x1b[0m\n";
let syslog_procs = exec_cmd("ps aux 2>/dev/null | grep -E 'rsyslog|syslog-ng|journald' | grep -v grep");
if syslog_procs.len() > 0 {
    for line in syslog_procs.split("\n") {
        if line.len() > 0 {
            output += "  " + line + "\n";
        }
    }
}
let remote_syslog = exec_cmd("grep -E '^[^#].*@@?' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -10");
if remote_syslog.len() > 0 {
    output += "  \x1b[1;33mRemote syslog forwarding detected:\x1b[0m\n";
    for line in remote_syslog.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    defenses_found += 1;
}

// --- Network security ---
output += "\n\x1b[1;4mNetwork Security:\x1b[0m\n";
let fail2ban = exec_cmd("systemctl is-active fail2ban 2>/dev/null");
if fail2ban.contains("active") {
    output += "  \x1b[33mfail2ban: ACTIVE\x1b[0m\n";
    let f2b_status = exec_cmd("fail2ban-client status 2>/dev/null | head -10");
    if f2b_status.len() > 0 {
        for line in f2b_status.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
    defenses_found += 1;
}

let ids_procs = exec_cmd("ps aux 2>/dev/null | grep -E 'snort|suricata|zeek|bro' | grep -v grep");
if ids_procs.len() > 0 {
    output += "  \x1b[1;31mIDS/IPS detected:\x1b[0m\n";
    for line in ids_procs.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    defenses_found += 1;
}

// --- File integrity monitoring ---
output += "\n\x1b[1;4mFile Integrity Monitoring:\x1b[0m\n";
let fim_tools = exec_cmd("which aide tripwire 2>/dev/null");
let fim_procs = exec_cmd("ps aux 2>/dev/null | grep -E 'aide|tripwire|ossec-syscheckd' | grep -v grep");
if fim_tools.len() > 0 || fim_procs.len() > 0 {
    if fim_tools.len() > 0 {
        output += "  \x1b[33mFIM tools installed: " + fim_tools.trim() + "\x1b[0m\n";
    }
    if fim_procs.len() > 0 {
        output += "  \x1b[33mFIM processes running:\x1b[0m\n";
        for line in fim_procs.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
    defenses_found += 1;
} else {
    output += "  (none detected)\n";
}

// --- Container security ---
let falco = exec_cmd("ps aux 2>/dev/null | grep -E 'falco|sysdig' | grep -v grep");
if falco.len() > 0 {
    output += "\n\x1b[1;4mContainer Security:\x1b[0m\n";
    output += "  \x1b[1;31mFalco/Sysdig detected:\x1b[0m\n";
    for line in falco.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    defenses_found += 1;
}

// --- Summary ---
output += "\n\x1b[1m" + defenses_found.to_string() + " defense(s) detected\x1b[0m\n";

print_output(output);

let RESULT = defenses_found.to_string() + " defense(s) detected";

let DATA = #{
    defenses_found: defenses_found,
    selinux_enforcing: selinux.contains("Enforcing"),
    apparmor_active: apparmor.len() > 0,
    auditd_active: auditd.contains("active"),
    fail2ban_active: fail2ban.contains("active"),
};
