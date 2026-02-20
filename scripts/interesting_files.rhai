// @name: interesting_files
// @description: Find high-value files — backups, databases, configs, secrets
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Interesting File Discovery ===\n";
let total_findings = 0;

// --- Backup files ---
output += "\n\x1b[1;4mBackup Files:\x1b[0m\n";
let backups = exec_cmd("timeout 25 find / -maxdepth 5 -type f \\( -name '*.bak' -o -name '*.old' -o -name '*.backup' -o -name '*.orig' -o -name '*.save' -o -name '*.copy' \\) ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -30");
if backups.len() > 0 {
    for line in backups.split("\n") {
        if line.len() > 0 {
            output += "  " + line + "\n";
            total_findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Database files ---
output += "\n\x1b[1;4mDatabase Files:\x1b[0m\n";
let databases = exec_cmd("timeout 25 find / -maxdepth 5 -type f \\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.sql' -o -name '*.dump' -o -name '*.mdb' \\) ! -path '/proc/*' ! -path '/sys/*' ! -path '/usr/share/*' 2>/dev/null | head -30");
if databases.len() > 0 {
    for line in databases.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            total_findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Password stores / Key files ---
output += "\n\x1b[1;4mPassword Stores & Key Files:\x1b[0m\n";
let key_files = exec_cmd("timeout 25 find / -maxdepth 5 -type f \\( -name '*.kdbx' -o -name '*.kdb' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jks' -o -name '*.keystore' \\) ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20");
if key_files.len() > 0 {
    for line in key_files.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[1;33m" + line + "\x1b[0m\n";
            total_findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- PEM / Certificate files ---
output += "\n\x1b[1;4mCertificates & PEM Files:\x1b[0m\n";
let pem_files = exec_cmd("timeout 15 find /etc /opt /home /root /var /srv -maxdepth 4 -type f \\( -name '*.pem' -o -name '*.crt' -o -name '*.cer' \\) 2>/dev/null | grep -v '/usr/share/ca-certificates' | head -20");
if pem_files.len() > 0 {
    for line in pem_files.split("\n") {
        if line.len() > 0 {
            output += "  " + line + "\n";
            total_findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Web application configs ---
output += "\n\x1b[1;4mWeb Application Configs:\x1b[0m\n";
let webapp_configs = [
    ["wp-config.php", "WordPress"],
    ["settings.py", "Django"],
    ["database.yml", "Rails"],
    ["config.php", "PHP App"],
    ["application.properties", "Spring Boot"],
    ["appsettings.json", "ASP.NET"],
    [".env", "Environment"],
    ["web.config", "IIS/ASP.NET"],
];

for entry in webapp_configs {
    let filename = entry[0];
    let label = entry[1];
    let found = exec_cmd("timeout 10 find /var/www /opt /srv /home -maxdepth 5 -name '" + filename + "' -type f 2>/dev/null | head -5");
    if found.len() > 0 {
        output += "  \x1b[33m" + label + ":\x1b[0m\n";
        for line in found.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
                // Preview sensitive lines
                let sensitive = exec_cmd("grep -iE 'password|pass|secret|key|token|db_|database' " + line + " 2>/dev/null | head -5");
                if sensitive.len() > 0 {
                    for s in sensitive.split("\n") {
                        if s.len() > 0 {
                            output += "      \x1b[2m" + s.trim() + "\x1b[0m\n";
                        }
                    }
                }
                total_findings += 1;
            }
        }
    }
}

// --- Git repositories ---
output += "\n\x1b[1;4mGit Repositories:\x1b[0m\n";
let git_repos = exec_cmd("timeout 20 find / -maxdepth 5 -name '.git' -type d ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -15");
if git_repos.len() > 0 {
    for line in git_repos.split("\n") {
        if line.len() > 0 {
            let config_path = line + "/config";
            let remote = exec_cmd("grep -A2 'remote' " + config_path + " 2>/dev/null | grep url | head -3");
            output += "  " + line + "\n";
            if remote.len() > 0 {
                for r in remote.split("\n") {
                    if r.len() > 0 {
                        output += "    \x1b[2m" + r.trim() + "\x1b[0m\n";
                    }
                }
            }
            total_findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Log files with potential secrets ---
output += "\n\x1b[1;4mLog Files (auth/access):\x1b[0m\n";
let logs = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
];

for log in logs {
    let readable = exec_cmd("test -r " + log + " && echo 'YES' || echo 'NO'");
    if readable.contains("YES") {
        let size = exec_cmd("du -h " + log + " 2>/dev/null");
        output += "  \x1b[33m" + log + "\x1b[0m " + size.trim() + "\n";
        total_findings += 1;
    }
}

// --- Configuration files with passwords ---
output += "\n\x1b[1;4mConfig Files with Passwords:\x1b[0m\n";
let config_passwords = exec_cmd("timeout 15 grep -rl --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.yml' --include='*.yaml' -iE 'password\\s*[:=]' /etc /opt 2>/dev/null | head -15");
if config_passwords.len() > 0 {
    for line in config_passwords.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            total_findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Summary ---
output += "\n\x1b[1m" + total_findings.to_string() + " interesting file(s) found\x1b[0m\n";

print_output(output);

let RESULT = total_findings.to_string() + " interesting file(s) found";

let DATA = #{
    total_findings: total_findings,
    has_backups: backups.len() > 0,
    has_databases: databases.len() > 0,
    has_key_files: key_files.len() > 0,
    has_git_repos: git_repos.len() > 0,
};
