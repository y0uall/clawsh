// @name: writable
// @description: Find world-writable directories and files
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

// World-writable directories (limited to 50 results)
let writable_dirs = exec_cmd("timeout 30 find / -writable -type d 2>/dev/null | head -50");

// World-writable files (limited, exclude /proc /sys /dev)
let writable_files = exec_cmd("timeout 30 find / -writable -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null | head -50");

// /tmp and /var/tmp contents
let tmp = exec_cmd("ls -la /tmp/ 2>/dev/null");
let var_tmp = exec_cmd("ls -la /var/tmp/ 2>/dev/null");

// Writable files in PATH directories
let path_writable = exec_cmd("timeout 15 sh -c 'find $(echo $PATH | tr \":\" \" \") -writable -type f 2>/dev/null'");

// Build output
let output = "=== Writable Locations ===\n";

output += "\n── World-writable directories (max 50) ──\n";
if writable_dirs.len() > 0 {
    output += writable_dirs + "\n";
} else {
    output += "(none found)\n";
}

output += "\n── World-writable files (max 50) ──\n";
if writable_files.len() > 0 {
    output += writable_files + "\n";
} else {
    output += "(none found)\n";
}

output += "\n── /tmp/ contents ──\n";
if tmp.len() > 0 {
    output += tmp + "\n";
} else {
    output += "(empty)\n";
}

output += "\n── /var/tmp/ contents ──\n";
if var_tmp.len() > 0 {
    output += var_tmp + "\n";
} else {
    output += "(empty)\n";
}

if path_writable.len() > 0 {
    output += "\n── Writable files in PATH ──\n";
    output += path_writable + "\n";
}

print_output(output);

let RESULT = "Writable location scan complete";

let dir_count = if writable_dirs.len() > 0 {
    writable_dirs.split("\n").len()
} else {
    0
};

let file_count = if writable_files.len() > 0 {
    writable_files.split("\n").len()
} else {
    0
};

let DATA = #{
    writable_dir_count: dir_count,
    writable_file_count: file_count,
    has_path_writable: path_writable.len() > 0,
};
