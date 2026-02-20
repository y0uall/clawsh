// @name: tool_hunt
// @description: Inventory of available LotL tools, compilers, and transfer binaries
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== LotL Tool Hunt (Living off the Land) ===\n";
let found_count = 0;

let categories = #{
    "Compilers/Build": ["gcc", "g++", "make", "cmake", "python3-dev", "go", "rustc"],
    "File Transfer": ["curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "tftp", "ftp"],
    "Interpreters": ["python3", "python2", "python", "perl", "ruby", "php", "node", "lua"],
    "Monitoring/Debug": ["strace", "ltrace", "gdb", "tcpdump", "wireshark", "tshark", "lsof"],
    "Security/Misc": ["nmap", "openssl", "gpg", "ssh", "base64", "strings", "sudo"]
};

for cat in categories.keys() {
    output += "\n\x1b[1;4m" + cat + ":\x1b[0m\n";
    let tools = categories[cat];
    let cat_found = false;

    for tool in tools {
        // 'command -v' is the most silent and fastest way to check for binaries
        let path = exec_cmd("command -v " + tool + " 2>/dev/null").trim();

        if path.len() > 0 {
            let version = "";
            // Try to get a version snippet (first line only, timeout fast)
            if tool == "gcc" || tool == "g++" || tool == "go" {
                version = exec_cmd(tool + " --version 2>/dev/null | head -n 1").trim();
            } else if tool == "python3" || tool == "python" {
                version = exec_cmd(tool + " -V 2>/dev/null").trim();
            }

            if version.len() > 0 {
                output += "  \x1b[32m[+]\x1b[0m " + tool.pad(15) + " -> " + path + " \x1b[2m(" + version + ")\x1b[0m\n";
            } else {
                output += "  \x1b[32m[+]\x1b[0m " + tool.pad(15) + " -> " + path + "\n";
            }
            found_count += 1;
            cat_found = true;
        }
    }

    if !cat_found {
        output += "  \x1b[2m(none found)\x1b[0m\n";
    }
}

output += "\n\x1b[1mSummary:\x1b[0m Found " + found_count.to_string() + " useful binaries.\n";
print_output(output);

let RESULT = "Tool hunt complete, found " + found_count.to_string() + " tools.";
let DATA = #{
    tools_found: found_count
};
