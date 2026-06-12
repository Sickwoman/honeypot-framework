# ELK Stack Configuration
# Elasticsearch, Logstash, Kibana for honeypot log aggregation and visualization

locals {
  elk_stack_config = {
    service_name = "ELK Stack (Elasticsearch, Logstash, Kibana)"
    
    elasticsearch = {
      port            = 9200
      cluster_name    = "honeypot-logs"
      node_name       = "es-node-1"
      data_directory  = "/var/lib/elasticsearch"
      heap_size       = "512m"
      status          = "pending"
    }
    
    logstash = {
      port           = 5000
      config_path    = "/etc/logstash/conf.d"
      input_sources = [
        "Cowrie logs from /home/cowrie/cowrie/var/log/cowrie/cowrie.log",
        "OpenCanary logs from /var/tmp/opencanary.log"
      ]
      filters = [
        "Parse JSON events",
        "Add GeoIP enrichment",
        "Extract source/destination IPs",
        "Tag by service type (cowrie vs opencanary)"
      ]
      output = "Send to Elasticsearch on port 9200"
      status = "pending"
    }
    
    kibana = {
      port           = 5601
      elasticsearch  = "http://localhost:9200"
      dashboards = [
        "Attack timeline (events per hour)",
        "Top source IPs",
        "Failed login attempts by country",
        "Service distribution (which ports attacked)",
        "Command execution patterns (Cowrie)"
      ]
      status = "pending"
    }
  }
}

output "elk_stack_configuration" {
  description = "ELK Stack deployment reference"
  value       = local.elk_stack_config
}

output "elk_deployment_roadmap" {
  description = "Phase 1.5 - ELK Stack implementation steps"
  value = {
    step_1 = "Install Elasticsearch + Kibana"
    step_2 = "Install Logstash and configure input/filter/output pipelines"
    step_3 = "Ship Cowrie logs to Logstash"
    step_4 = "Ship OpenCanary logs to Logstash"
    step_5 = "Create Kibana index patterns and dashboards"
    step_6 = "Add GeoIP enrichment for source IPs"
    step_7 = "Test with simulated attack data"
  }
}
