// @name: proc_enum
// @description: Advanced process enumeration and analysis
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Advanced Process Enumeration ===\n";

// --- Process tree ---
output += "\n\x1b[1;4mProcess Tree:\x1b[0m\n";
let ps_tree = exec_cmd("ps auxf 2>/dev/null | head -80");
if ps_tree.len() > 0 {
    output += ps_tree + "\n";
} else {
    let ps_basic = exec_cmd("ps aux 2>/dev/null | head -80");
    if ps_basic.len() > 0 {
        output += ps_basic + "\n";
    } else {
        output += "(ps not available)\n";
    }
}

// --- Interesting processes ---
output += "\n\x1b[1;4mInteresting Processes:\x1b[0m\n";

let interesting = [
    ["mysql|mariadbd|postgres|mongod|redis-server|memcached", "Databases"],
    ["apache|httpd|nginx|lighttpd|caddy", "Web Servers"],
    ["docker|containerd|podman|crio", "Container Runtime"],
    ["sshd|vsftpd|proftpd|smbd|nmbd", "Remote Access"],
    ["postfix|sendmail|dovecot|exim", "Mail Services"],
    ["named|dnsmasq|unbound", "DNS"],
    ["openvpn|wireguard|strongswan", "VPN"],
    ["cron|atd|anacron", "Schedulers"],
    ["java|tomcat|node|python.*server|gunicorn|uwsgi", "Application Servers"],
];

let found_interesting = 0;
for entry in interesting {
    let pattern = entry[0];
    let label = entry[1];
    let result = exec_cmd("ps aux 2>/dev/null | grep -iE '" + pattern + "' | grep -v grep | head -5");
    if result.len() > 0 {
        output += "\n  \x1b[33m" + label + ":\x1b[0m\n";
        for line in result.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
        found_interesting += 1;
    }
}

if found_interesting == 0 {
    output += "  (no notable services detected)\n";
}

// --- Root processes with open ports ---
output += "\n\x1b[1;4mRoot-Owned Listening Services:\x1b[0m\n";
let root_listening = exec_cmd("ss -tlnp 2>/dev/null | grep -v 'State' | head -30");
if root_listening.len() > 0 {
    for line in root_listening.split("\n") {
        if line.len() > 0 {
            output += "  " + line + "\n";
        }
    }
} else {
    output += "  (ss not available)\n";
}

// --- ptrace scope ---
output += "\n\x1b[1;4mSecurity Settings:\x1b[0m\n";
let ptrace = exec_cmd("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null");
if ptrace.len() > 0 {
    let scope = ptrace.trim();
    if scope == "0" {
        output += "  \x1b[33mptrace_scope: 0 (any process can ptrace)\x1b[0m\n";
    } else if scope == "1" {
        output += "  ptrace_scope: 1 (parent only)\n";
    } else if scope == "2" {
        output += "  ptrace_scope: 2 (admin only)\n";
    } else if scope == "3" {
        output += "  ptrace_scope: 3 (disabled)\n";
    } else {
        output += "  ptrace_scope: " + scope + "\n";
    }
} else {
    output += "  ptrace_scope: (not available)\n";
}

// --- Core dumps ---
let core_pattern = exec_cmd("cat /proc/sys/kernel/core_pattern 2>/dev/null");
if core_pattern.len() > 0 {
    output += "  core_pattern: " + core_pattern.trim() + "\n";
    if core_pattern.contains("|") {
        output += "    \x1b[33m(piped to external handler — may be exploitable)\x1b[0m\n";
    }
}

// --- Process limits ---
let proc_limit = exec_cmd("ulimit -a 2>/dev/null | head -20");
if proc_limit.len() > 0 {
    output += "\n\x1b[1;4mProcess Limits (ulimit):\x1b[0m\n";
    for line in proc_limit.split("\n") {
        if line.len() > 0 {
            output += "  " + line + "\n";
        }
    }
}

// --- /proc/sched_debug (may leak process info) ---
let sched_debug = exec_cmd("cat /proc/sched_debug 2>/dev/null | head -5");
if sched_debug.len() > 0 {
    output += "\n  \x1b[33m/proc/sched_debug is readable (process info leak)\x1b[0m\n";
}

print_output(output);

let RESULT = found_interesting.to_string() + " interesting service categories found";

let DATA = #{
    interesting_services: found_interesting,
    ptrace_scope: ptrace.trim(),
    has_core_pipe: core_pattern.contains("|"),
    sched_debug_readable: sched_debug.len() > 0,
};
