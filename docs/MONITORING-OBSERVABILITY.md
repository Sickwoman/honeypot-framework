# Monitoring & Observability Guide

## Overview

Complete monitoring setup with Prometheus metrics, Grafana dashboards, and real-time alerting.

---

## 1. Install Prometheus

### Using Docker

```bash
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v ~/Desktop/honeypot-framework/config/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v ~/Desktop/honeypot-framework/config/alert_rules.yml:/etc/prometheus/alert_rules.yml \
  prom/prometheus
```

### Access Prometheus
http://localhost:9090
### Verify Scraping

1. Go to Status → Targets
2. Check all jobs are "UP"

---

## 2. Install Node Exporter

### Linux Installation

```bash
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
```

### Run Node Exporter

```bash
node_exporter &
```

### Verify

```bash
curl http://localhost:9100/metrics | head -20
```

---

## 3. Start Honeypot Metrics Exporter

### Run Exporter

```bash
python3 ~/Desktop/honeypot-framework/scripts/prometheus-exporter.py
```

### Verify Metrics

```bash
curl http://localhost:8000/metrics | head -20
```

### Add to Systemd

```bash
cat > /etc/systemd/system/honeypot-exporter.service << 'EOFSERVICE'
[Unit]
Description=Honeypot Prometheus Exporter
After=network.target

[Service]
Type=simple
User=moksh
WorkingDirectory=/home/moksh/Desktop/honeypot-framework
ExecStart=/usr/bin/python3 scripts/prometheus-exporter.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOFSERVICE

sudo systemctl daemon-reload
sudo systemctl enable honeypot-exporter
sudo systemctl start honeypot-exporter
```

---

## 4. Install Grafana

### Using Docker

```bash
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  grafana/grafana
```

### Access Grafana
http://localhost:3000
Login: admin / admin
### Add Prometheus Data Source

1. Go to Configuration → Data Sources
2. Click "Add data source"
3. Select "Prometheus"
4. URL: http://localhost:9090
5. Click "Save & test"

### Import Dashboard

1. Go to Dashboards → New → Import
2. Upload: config/grafana-dashboard.json
3. Select Prometheus data source
4. Click "Import"

---

## 5. Key Metrics to Monitor

### Attack Metrics

- **honeypot_events_total** - Total events captured
- **honeypot_attack_rate** - Attacks per minute
- **honeypot_unique_ips** - Unique attacking IPs
- **honeypot_credentials_total** - Credentials captured

### Threat Metrics

- **honeypot_threat_level_high** - HIGH risk IPs
- **honeypot_threat_level_medium** - MEDIUM risk IPs

### System Metrics

- **elasticsearch_cluster_health_status** - Cluster health
- **elasticsearch_documents_total** - Total documents
- **node_memory_MemAvailable_bytes** - Available memory
- **node_filesystem_avail_bytes** - Available disk space

---

## 6. Create Custom Alerts

### Alert: High Attack Volume

```yaml
- alert: HighAttackVolume
  expr: rate(honeypot_events_total[5m]) > 10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High attack volume detected"
```

### Alert: Service Down

```yaml
- alert: ServiceDown
  expr: up{job=~"cowrie|opencanary"} == 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "{{ $labels.job }} service is down"
```

### Alert: Low Disk Space

```yaml
- alert: DiskSpaceLow
  expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Low disk space ({{ $value | humanizePercentage }})"
```

---

## 7. Useful Prometheus Queries

### Attack Rate

rate(honeypot_events_total[5m])
### Top Attacking IPs
topk(10, honeypot_events_total)
### Cluster Health
### Memory Usage Percentage
100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))
### Disk Usage Percentage
100 * (1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes))
---

## 8. Grafana Dashboards

### Available Panels

1. **Attack Rate** - Line chart of attacks over time
2. **Total Events** - Single stat
3. **Unique IPs** - Gauge
4. **Threat Levels** - Pie chart
5. **Cluster Health** - Stat with color coding
6. **Documents** - Time series

### Create Custom Panel

1. Click "Add panel"
2. Select visualization type
3. Enter Prometheus query
4. Configure axes and legend
5. Click "Save"

---

## 9. Set Up Alertmanager

### Install Alertmanager

```bash
wget https://github.com/prometheus/alertmanager/releases/download/v0.25.0/alertmanager-0.25.0.linux-amd64.tar.gz
tar xvfz alertmanager-0.25.0.linux-amd64.tar.gz
sudo mv alertmanager-0.25.0.linux-amd64/alertmanager /usr/local/bin/
```

### Configure Alertmanager

```bash
cat > alertmanager.yml << 'EOFCONFIG'
global:
  resolve_timeout: 5m

route:
  receiver: 'slack'
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h

receivers:
  - name: 'slack'
    slack_configs:
      - api_url: $SLACK_WEBHOOK_URL
        channel: '#security-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

EOFCONFIG
```

### Run Alertmanager

```bash
alertmanager --config.file=alertmanager.yml
```

---

## 10. Monitoring Dashboard Checklist

- [ ] Prometheus running
- [ ] All scrape targets UP
- [ ] Node exporter running
- [ ] Honeypot exporter running
- [ ] Grafana accessing Prometheus
- [ ] Dashboard imported
- [ ] Alerts configured
- [ ] Alertmanager running
- [ ] Slack webhook integrated
- [ ] Test alert sent

---

## 11. Troubleshooting

### Prometheus targets down

```bash
# Check service status
curl http://localhost:9100/metrics

# Restart service
sudo systemctl restart honeypot-exporter
```

### No data in Grafana

```bash
# Check data source connection
# Go to Data Sources → Prometheus → Test

# Run query in Prometheus
# http://localhost:9090 → Graph
```

### Alerts not firing

```bash
# Check alert rules syntax
promtool check rules alert_rules.yml

# Verify alert in Prometheus
# http://localhost:9090 → Alerts
```

---

## 12. Performance Optimization

### Scrape Interval

```yaml
global:
  scrape_interval: 15s  # Default
  # Increase for lower load: 30s
  # Decrease for real-time: 5s
```

### Retention

```bash
# Prometheus command line
--storage.tsdb.retention.time=15d  # Keep 15 days
```

### Query Optimization
Slow query
rate(honeypot_events_total[5m])
Better with recording rule
honeypot:events:rate5m
---

## 13. Quick Reference Commands

```bash
# Start all monitoring
docker run -d -p 9090:9090 -v $(pwd)/config/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus
docker run -d -p 3000:3000 grafana/grafana
python3 scripts/prometheus-exporter.py
node_exporter

# Access services
http://localhost:9090          # Prometheus
http://localhost:3000          # Grafana
http://localhost:8000/metrics  # Honeypot metrics
http://localhost:9100/metrics  # Node metrics

# Check metrics
curl http://localhost:8000/metrics
curl http://localhost:9100/metrics

# Restart services
sudo systemctl restart honeypot-exporter
docker restart prometheus grafana
```

---

## 14. Next Steps

1. Install Prometheus and Grafana
2. Start honeypot metrics exporter
3. Add Prometheus data source in Grafana
4. Import dashboard
5. Create custom alerts
6. Set up Alertmanager
7. Integrate with Slack/Discord
8. Monitor and optimize

