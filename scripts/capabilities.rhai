// @name: capabilities
// @description: Enumerate Linux capabilities on binaries
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

// Find binaries with capabilities
let caps = exec_cmd("timeout 30 getcap -r / 2>/dev/null");

// Current process capabilities
let proc_caps = exec_cmd("cat /proc/self/status 2>/dev/null | grep -i cap");

// Known interesting capabilities for privilege escalation
let interesting = [
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_net_raw",
    "cap_net_admin",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_fowner",
    "cap_chown",
];

// Build output
let output = "=== Linux Capabilities ===\n";

output += "\n── Current process capabilities ──\n";
if proc_caps.len() > 0 {
    output += proc_caps + "\n";
} else {
    output += "(not readable)\n";
}

output += "\n── Binaries with capabilities ──\n";
if caps.len() > 0 {
    let lines = caps.split("\n");
    let interesting_found = [];

    for line in lines {
        if line.len() == 0 { continue; }

        let is_interesting = false;
        for cap in interesting {
            if line.contains(cap) {
                is_interesting = true;
            }
        }

        if is_interesting {
            output += "  \x1b[1;33m★\x1b[0m " + line + "\n";
            interesting_found.push(line);
        } else {
            output += "    " + line + "\n";
        }
    }

    if interesting_found.len() > 0 {
        output += "\n  \x1b[33m" + interesting_found.len().to_string() + " interesting binaries found (marked with ★)\x1b[0m\n";
    }
} else {
    output += "(getcap not available or no capabilities set)\n";
}

print_output(output);

let cap_count = if caps.len() > 0 {
    caps.split("\n").len()
} else {
    0
};

let RESULT = "Capability scan complete — " + cap_count.to_string() + " binaries found";

let DATA = #{
    total_binaries: cap_count,
    has_caps: caps.len() > 0,
};
