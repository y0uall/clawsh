// @name: container_escape
// @description: Detect containerization and escape vectors
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

// --- Container detection ---
let dockerenv = exec_cmd("test -f /.dockerenv && echo 'YES' || echo 'NO'");
let containerenv = exec_cmd("test -f /run/.containerenv && echo 'YES' || echo 'NO'");
let cgroup = exec_cmd("cat /proc/1/cgroup 2>/dev/null | head -20");
let hostname_check = exec_cmd("hostname 2>/dev/null");
let init_proc = exec_cmd("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '");

// Determine container type
let container_type = "none";
if dockerenv.contains("YES") {
    container_type = "docker";
} else if containerenv.contains("YES") {
    container_type = "podman/lxc";
} else if cgroup.contains("docker") || cgroup.contains("containerd") {
    container_type = "docker (cgroup)";
} else if cgroup.contains("lxc") {
    container_type = "lxc";
} else if cgroup.contains("kubepods") {
    container_type = "kubernetes";
}

// Kubernetes detection
let k8s_sa = exec_cmd("test -d /var/run/secrets/kubernetes.io && echo 'YES' || echo 'NO'");
let k8s_env = exec_cmd("env 2>/dev/null | grep -i KUBERNETES | head -10");
let k8s_token = exec_cmd("cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50");

// --- Escape vectors ---
let docker_sock = exec_cmd("ls -la /var/run/docker.sock 2>/dev/null");
let docker_sock_writable = exec_cmd("test -w /var/run/docker.sock && echo 'WRITABLE' || echo 'NO'");

// Privileged mode check via capabilities
let capeff = exec_cmd("cat /proc/1/status 2>/dev/null | grep CapEff");
let is_privileged = false;
if capeff.contains("0000003fffffffff") || capeff.contains("000001ffffffffff") {
    is_privileged = true;
}

// nsenter / chroot availability
let nsenter = exec_cmd("which nsenter 2>/dev/null");
let chroot_avail = exec_cmd("which chroot 2>/dev/null");

// Host PID namespace (can we see host processes?)
let host_pid = exec_cmd("ps aux 2>/dev/null | wc -l");

// Mounted host filesystems
let mounts = exec_cmd("mount 2>/dev/null | grep -E '/ type|/host|/rootfs' | head -20");
let sensitive_mounts = exec_cmd("mount 2>/dev/null | grep -E '/etc|/root|/home|/var' | head -20");

// Writable sysfs (needed for some escapes)
let sys_writable = exec_cmd("test -w /sys && echo 'WRITABLE' || echo 'NO'");

// Device access
let devices = exec_cmd("ls /dev/sd* /dev/vd* /dev/xvd* 2>/dev/null | head -10");

// cgroup release_agent (CVE-2022-0492)
let release_agent = exec_cmd("cat /sys/fs/cgroup/*/release_agent 2>/dev/null | head -5");
let cgroup_writable = exec_cmd("test -w /sys/fs/cgroup/ && echo 'WRITABLE' || echo 'NO'");

// --- Build output ---
let output = "=== Container & Escape Vector Detection ===\n";

output += "\n\x1b[1;4mContainer Detection:\x1b[0m\n";
output += "  Container type:  " + container_type + "\n";
output += "  /.dockerenv:     " + dockerenv.trim() + "\n";
output += "  /run/.containerenv: " + containerenv.trim() + "\n";
output += "  Hostname:        " + hostname_check.trim() + "\n";
output += "  Init process:    " + init_proc.trim() + "\n";

if cgroup.len() > 0 {
    output += "\n  \x1b[2mCgroups:\x1b[0m\n";
    for line in cgroup.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
}

if k8s_sa.contains("YES") || k8s_env.len() > 0 {
    output += "\n\x1b[1;4mKubernetes:\x1b[0m\n";
    output += "  Service account: " + k8s_sa.trim() + "\n";
    if k8s_token.len() > 0 {
        output += "  \x1b[1;33mSA Token found!\x1b[0m " + k8s_token + "...\n";
    }
    if k8s_env.len() > 0 {
        output += "  K8s env vars:\n";
        for line in k8s_env.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
}

output += "\n\x1b[1;4mEscape Vectors:\x1b[0m\n";

let escape_count = 0;

if docker_sock.len() > 0 {
    if docker_sock_writable.contains("WRITABLE") {
        output += "  \x1b[1;31m[!] Docker socket WRITABLE: " + docker_sock.trim() + "\x1b[0m\n";
        output += "      \x1b[33mEscape: docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host\x1b[0m\n";
        escape_count += 1;
    } else {
        output += "  [*] Docker socket exists: " + docker_sock.trim() + " (not writable)\n";
    }
}

if is_privileged {
    output += "  \x1b[1;31m[!] PRIVILEGED MODE DETECTED (full capabilities)\x1b[0m\n";
    output += "      \x1b[33mEscape: mount host disk + chroot, or nsenter --target 1 --mount --uts --ipc --net --pid\x1b[0m\n";
    escape_count += 1;
}

if nsenter.len() > 0 {
    output += "  \x1b[1;33m[*] nsenter available: " + nsenter.trim() + "\x1b[0m\n";
    escape_count += 1;
}

if sys_writable.contains("WRITABLE") {
    output += "  \x1b[1;33m[*] /sys is writable (cgroup escape possible)\x1b[0m\n";
    escape_count += 1;
}

if cgroup_writable.contains("WRITABLE") {
    output += "  \x1b[1;33m[*] /sys/fs/cgroup writable (release_agent escape CVE-2022-0492)\x1b[0m\n";
    escape_count += 1;
}

if devices.len() > 0 {
    output += "  \x1b[1;33m[*] Host block devices accessible:\x1b[0m\n";
    for line in devices.split("\n") {
        if line.len() > 0 {
            output += "      " + line + "\n";
        }
    }
    escape_count += 1;
}

if sensitive_mounts.len() > 0 {
    output += "\n  \x1b[2mSensitive mounts:\x1b[0m\n";
    for line in sensitive_mounts.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }
}

if escape_count == 0 {
    output += "  (no obvious escape vectors found)\n";
}

output += "\n  Capabilities (PID 1): " + capeff.trim() + "\n";

print_output(output);

let RESULT = "Container: " + container_type + ", " + escape_count.to_string() + " escape vector(s)";

let DATA = #{
    container_type: container_type,
    is_privileged: is_privileged,
    docker_socket_writable: docker_sock_writable.contains("WRITABLE"),
    kubernetes: k8s_sa.contains("YES"),
    escape_vectors: escape_count,
};
