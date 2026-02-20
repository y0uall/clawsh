// @name: cron_enum
// @description: Enumerate cron jobs, crontabs, and systemd timers
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

// System-wide crontab
let system_cron = exec_cmd("cat /etc/crontab 2>/dev/null");

// Cron directories
let cron_d = exec_cmd("ls -la /etc/cron.d/ 2>/dev/null");
let cron_daily = exec_cmd("ls /etc/cron.daily/ 2>/dev/null");
let cron_hourly = exec_cmd("ls /etc/cron.hourly/ 2>/dev/null");
let cron_weekly = exec_cmd("ls /etc/cron.weekly/ 2>/dev/null");
let cron_monthly = exec_cmd("ls /etc/cron.monthly/ 2>/dev/null");

// Per-user crontabs
let user_cron = exec_cmd("crontab -l 2>/dev/null");
let all_crontabs = exec_cmd("ls -la /var/spool/cron/crontabs/ 2>/dev/null");

// Systemd timers
let timers = exec_cmd("systemctl list-timers --all --no-pager 2>/dev/null");

// At jobs
let at_jobs = exec_cmd("atq 2>/dev/null");

// Build output
let output = "=== Cron Enumeration ===\n";

output += "\n── /etc/crontab ──\n";
if system_cron.len() > 0 {
    output += system_cron + "\n";
} else {
    output += "(empty or not readable)\n";
}

output += "\n── /etc/cron.d/ ──\n";
if cron_d.len() > 0 {
    output += cron_d + "\n";
} else {
    output += "(empty)\n";
}

output += "\n── Periodic directories ──\n";
if cron_daily.len() > 0 { output += "daily:   " + cron_daily.replace("\n", ", ") + "\n"; }
if cron_hourly.len() > 0 { output += "hourly:  " + cron_hourly.replace("\n", ", ") + "\n"; }
if cron_weekly.len() > 0 { output += "weekly:  " + cron_weekly.replace("\n", ", ") + "\n"; }
if cron_monthly.len() > 0 { output += "monthly: " + cron_monthly.replace("\n", ", ") + "\n"; }

output += "\n── Current user crontab ──\n";
if user_cron.len() > 0 {
    output += user_cron + "\n";
} else {
    output += "(no crontab for current user)\n";
}

output += "\n── All user crontabs ──\n";
if all_crontabs.len() > 0 {
    output += all_crontabs + "\n";
} else {
    output += "(not readable or empty)\n";
}

output += "\n── Systemd timers ──\n";
if timers.len() > 0 {
    output += timers + "\n";
} else {
    output += "(systemctl not available)\n";
}

if at_jobs.len() > 0 {
    output += "\n── At jobs ──\n";
    output += at_jobs + "\n";
}

print_output(output);

// Store result
let RESULT = "Cron enumeration complete";

// Structured data
let DATA = #{
    has_system_cron: system_cron.len() > 0,
    has_user_cron: user_cron.len() > 0,
    has_timers: timers.len() > 0,
    has_at_jobs: at_jobs.len() > 0,
};
