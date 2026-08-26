# PQC SSH Honeypot Configuration
# Documents the EC2-native post-quantum SSH honeypot for Terraform reference.
# Production form of pqc-poc/ (Docker PoC). Provisioning: user_data.pqc.sh.

locals {
  pqc_ssh_config = {
    service_name      = "PQC SSH Honeypot (observation)"
    variant           = "ec2-hybrid"
    listen_port       = 2223
    host_key          = "/etc/ssh/pqc-keys/ssh_host_ed25519_key"
    config_file       = "/etc/ssh/sshd_config.pqc-honeypot"
    runner            = "/usr/local/bin/pqc-honeypot-run.sh"
    systemd_unit      = "pqc-honeypot.service"
    log_directory     = "/var/log/pqc-honeypot"
    log_file          = "/var/log/pqc-honeypot/events.json"

    # KexAlgorithms are chosen at boot from `ssh -Q kex`: sntrup761 is always
    # advertised (PQC, OpenSSH >= 8.5); ML-KEM hybrid is added iff supported.
    kex_always        = "sntrup761x25519-sha512@openssh.com"
    kex_if_supported  = "mlkem768x25519-sha256" # needs OpenSSH >= 9.9

    captured_data = {
      kex_algorithm  = "the exact key exchange each client negotiated"
      post_quantum   = "boolean: did the client speak PQC or fall back to classical"
    }

    # Not this variant (kept faithful to the PoC's split):
    excluded = {
      credential_capture = "separate Docker relay -- see pqc-poc/handoff/"
      pqc_only           = "pure non-hybrid kex needs OQS-OpenSSH, not stock OpenSSH"
    }
  }
}

output "pqc_ssh_configuration" {
  description = "PQC SSH honeypot deployment reference"
  value       = local.pqc_ssh_config
}

output "pqc_ssh_deployment_guide" {
  description = "PQC SSH honeypot setup notes"
  value = {
    provision = "append honeypots/pqc-ssh/user_data.pqc.sh to terraform/modules/aws-ec2/user_data.sh (or run standalone on Ubuntu)"
    firewall  = "open TCP 2223 to 0.0.0.0/0 in terraform/modules/aws-security-group/main.tf (see README)"
    status    = "systemctl status pqc-honeypot.service"
    logs      = "tail -f /var/log/pqc-honeypot/events.json"
    verify    = "ssh -o KexAlgorithms=sntrup761x25519-sha512@openssh.com -p 2223 x@<ip> ; then check events.json for post_quantum:true"
  }
}
