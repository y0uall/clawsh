// @name: ssh_enum
// @description: SSH configuration, keys, known hosts, and agent analysis
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== SSH Enumeration ===\n";
let findings = 0;

// --- sshd_config ---
output += "\n\x1b[1;4mSSHD Configuration:\x1b[0m\n";
let sshd_config = exec_cmd("cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#|^$' | head -40");
if sshd_config.len() > 0 {
    let interesting_keys = [
        "PermitRootLogin",
        "PasswordAuthentication",
        "PubkeyAuthentication",
        "AuthorizedKeysFile",
        "AllowUsers",
        "AllowGroups",
        "DenyUsers",
        "PermitEmptyPasswords",
        "X11Forwarding",
        "AllowTcpForwarding",
        "GatewayPorts",
        "PermitTunnel",
        "AllowAgentForwarding",
    ];
    for line in sshd_config.split("\n") {
        if line.len() == 0 { continue; }
        let is_interesting = false;
        for key in interesting_keys {
            if line.contains(key) {
                is_interesting = true;
            }
        }
        if is_interesting {
            if line.contains("PermitRootLogin yes") || line.contains("PermitEmptyPasswords yes") {
                output += "  \x1b[1;31m" + line + "\x1b[0m\n";
                findings += 1;
            } else {
                output += "  \x1b[33m" + line + "\x1b[0m\n";
            }
        }
    }
} else {
    output += "  (not readable)\n";
}

// --- Current user SSH directory ---
output += "\n\x1b[1;4mCurrent User SSH (~/.ssh/):\x1b[0m\n";
let ssh_dir = exec_cmd("ls -la ~/.ssh/ 2>/dev/null");
if ssh_dir.len() > 0 {
    for line in ssh_dir.split("\n") {
        if line.len() > 0 {
            if line.contains("id_rsa") || line.contains("id_ed25519") || line.contains("id_ecdsa") {
                output += "  \x1b[33m" + line + "\x1b[0m\n";
                findings += 1;
            } else {
                output += "  " + line + "\n";
            }
        }
    }
} else {
    output += "  (no .ssh directory)\n";
}

// --- SSH config ---
output += "\n\x1b[1;4mSSH Client Config (~/.ssh/config):\x1b[0m\n";
let ssh_config = exec_cmd("cat ~/.ssh/config 2>/dev/null | head -50");
if ssh_config.len() > 0 {
    for line in ssh_config.split("\n") {
        if line.len() == 0 { continue; }
        if line.contains("ProxyJump") || line.contains("ForwardAgent") || line.contains("IdentityFile") {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            findings += 1;
        } else if line.contains("Host ") {
            output += "  \x1b[1m" + line + "\x1b[0m\n";
        } else {
            output += "  " + line + "\n";
        }
    }
} else {
    output += "  (not found)\n";
}

// --- Authorized keys ---
output += "\n\x1b[1;4mAuthorized Keys:\x1b[0m\n";
let auth_keys = exec_cmd("cat ~/.ssh/authorized_keys 2>/dev/null | head -20");
if auth_keys.len() > 0 {
    let key_count = 0;
    for line in auth_keys.split("\n") {
        if line.len() > 0 && !line.starts_with("#") {
            key_count += 1;
            // Show key type and comment (last field)
            let parts = line.split(" ");
            if parts.len() >= 2 {
                let key_type = parts[0];
                let comment = if parts.len() >= 3 { parts[parts.len() - 1] } else { "" };
                output += "  " + key_type + " ..." + comment + "\n";
            } else {
                output += "  " + line + "\n";
            }
        }
    }
    output += "  (" + key_count.to_string() + " authorized key(s))\n";
} else {
    output += "  (none or not readable)\n";
}

// --- Known hosts (unique hosts) ---
output += "\n\x1b[1;4mKnown Hosts:\x1b[0m\n";
let known_hosts = exec_cmd("cat ~/.ssh/known_hosts 2>/dev/null | head -30");
if known_hosts.len() > 0 {
    let host_count = 0;
    for line in known_hosts.split("\n") {
        if line.len() > 0 && !line.starts_with("#") {
            host_count += 1;
            let parts = line.split(" ");
            if parts.len() >= 1 {
                let host = parts[0];
                if !host.contains("|") {
                    // Not hashed — show the hostname/IP
                    output += "  \x1b[33m" + host + "\x1b[0m\n";
                }
            }
        }
    }
    output += "  (" + host_count.to_string() + " known host(s))\n";
    findings += 1;
} else {
    output += "  (none or not readable)\n";
}

// --- SSH agent ---
output += "\n\x1b[1;4mSSH Agent:\x1b[0m\n";
let ssh_auth_sock = exec_cmd("echo $SSH_AUTH_SOCK 2>/dev/null");
if ssh_auth_sock.trim().len() > 0 {
    output += "  SSH_AUTH_SOCK: " + ssh_auth_sock.trim() + "\n";
    let agent_keys = exec_cmd("ssh-add -l 2>/dev/null");
    if agent_keys.len() > 0 && !agent_keys.contains("no identities") && !agent_keys.contains("not open") {
        output += "  \x1b[1;33mAgent keys loaded:\x1b[0m\n";
        for line in agent_keys.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
        findings += 1;
    } else {
        output += "  (no keys loaded or agent not running)\n";
    }
} else {
    output += "  (no SSH agent socket)\n";
}

// --- Other users' SSH directories ---
output += "\n\x1b[1;4mOther Users' SSH Directories:\x1b[0m\n";
let other_ssh = exec_cmd("timeout 10 find /home /root -maxdepth 3 \\( -name 'authorized_keys' -o -name 'id_rsa' -o -name 'id_ed25519' \\) 2>/dev/null | head -20");
if other_ssh.len() > 0 {
    for line in other_ssh.split("\n") {
        if line.len() > 0 {
            let readable = exec_cmd("test -r " + line + " && echo 'READABLE' || echo 'NO'");
            if readable.contains("READABLE") {
                output += "  \x1b[1;33m" + line + " (readable!)\x1b[0m\n";
                findings += 1;
            } else {
                output += "  " + line + "\n";
            }
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Host keys ---
output += "\n\x1b[1;4mHost Keys:\x1b[0m\n";
let host_keys = exec_cmd("ls -la /etc/ssh/ssh_host_* 2>/dev/null");
if host_keys.len() > 0 {
    for line in host_keys.split("\n") {
        if line.len() > 0 {
            output += "  " + line + "\n";
        }
    }
} else {
    output += "  (not readable)\n";
}

print_output(output);

let RESULT = findings.to_string() + " SSH finding(s)";

let DATA = #{
    findings: findings,
    has_ssh_dir: ssh_dir.len() > 0,
    has_ssh_config: ssh_config.len() > 0,
    has_agent: ssh_auth_sock.trim().len() > 0,
    sshd_config_readable: sshd_config.len() > 0,
};
