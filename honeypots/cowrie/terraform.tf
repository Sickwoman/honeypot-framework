# Cowrie SSH Honeypot Configuration
# This file documents the Cowrie deployment for Terraform reference

locals {
  cowrie_config = {
    service_name         = "Cowrie SSH Honeypot"
    version              = "latest"
    listen_port          = 2222
    fake_hostname        = "webserver01"
    username             = "cowrie"
    installation_path    = "/home/cowrie/cowrie"
    virtual_env          = "/home/cowrie/cowrie-env"
    log_directory        = "/home/cowrie/cowrie/var/log/cowrie"
    config_file          = "/home/cowrie/cowrie/etc/cowrie.cfg"
    
    captured_data = {
      ssh_login_attempts  = "username:password combinations"
      commands_executed   = "fake shell commands and payloads"
      file_downloads      = "attempted malware downloads"
      tty_recordings      = "full session replays"
    }
    
    enabled_services = [
      "SSH/Telnet emulation",
      "Command logging",
      "TTY session recording",
      "File download interception"
    ]
  }
}

output "cowrie_configuration" {
  description = "Cowrie deployment reference"
  value       = local.cowrie_config
}

output "cowrie_deployment_guide" {
  description = "Cowrie setup commands"
  value = {
    install = "sudo apt install python3 python3-pip git libssl-dev libffi-dev build-essential -y && git clone https://github.com/cowrie/cowrie.git && cd cowrie && python3 -m venv cowrie-env && source cowrie-env/bin/activate && pip install -r requirements.txt"
    configure = "cp etc/cowrie.cfg.dist etc/cowrie.cfg && nano etc/cowrie.cfg"
    start = "bin/cowrie start"
    status = "bin/cowrie status"
    logs = "cat var/log/cowrie/cowrie.log | tail -50"
  }
}
