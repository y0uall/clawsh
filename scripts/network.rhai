// @name: network
// @description: Network interfaces, routes, listening ports, ARP, DNS
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

// Network interfaces
let ip_addr = exec_cmd("ip addr 2>/dev/null || ifconfig -a 2>/dev/null");

// Listening ports
let listening = exec_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null");

// All connections
let connections = exec_cmd("ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null");

// Routes
let routes = exec_cmd("ip route 2>/dev/null || route -n 2>/dev/null");

// DNS config
let resolv = exec_cmd("cat /etc/resolv.conf 2>/dev/null");

// ARP table
let arp = exec_cmd("ip neigh 2>/dev/null || arp -a 2>/dev/null");

// Hosts file
let hosts = exec_cmd("cat /etc/hosts 2>/dev/null");

// Firewall rules
let iptables = exec_cmd("iptables -L -n 2>/dev/null");
let nftables = exec_cmd("nft list ruleset 2>/dev/null");

// Build output
let output = "=== Network Enumeration ===\n";

output += "\n── Interfaces ──\n";
if ip_addr.len() > 0 {
    output += ip_addr + "\n";
} else {
    output += "(no interface info available)\n";
}

output += "\n── Listening ports ──\n";
if listening.len() > 0 {
    output += listening + "\n";
} else {
    output += "(no info available)\n";
}

output += "\n── Established connections ──\n";
if connections.len() > 0 {
    output += connections + "\n";
} else {
    output += "(no info available)\n";
}

output += "\n── Routes ──\n";
if routes.len() > 0 {
    output += routes + "\n";
} else {
    output += "(no routing info)\n";
}

output += "\n── DNS (/etc/resolv.conf) ──\n";
if resolv.len() > 0 {
    output += resolv + "\n";
} else {
    output += "(not readable)\n";
}

output += "\n── ARP table ──\n";
if arp.len() > 0 {
    output += arp + "\n";
} else {
    output += "(empty or not available)\n";
}

output += "\n── /etc/hosts ──\n";
if hosts.len() > 0 {
    output += hosts + "\n";
}

if iptables.len() > 0 {
    output += "\n── iptables rules ──\n";
    output += iptables + "\n";
}

if nftables.len() > 0 {
    output += "\n── nftables rules ──\n";
    output += nftables + "\n";
}

print_output(output);

let RESULT = "Network enumeration complete";

let DATA = #{
    has_interfaces: ip_addr.len() > 0,
    has_listening: listening.len() > 0,
    has_firewall: iptables.len() > 0 || nftables.len() > 0,
};
