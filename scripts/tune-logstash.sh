#!/bin/bash

################################################################################
# Logstash Performance Tuning Script
# Optimizes pipeline workers, batch sizes, and throughput
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  ⚙️  LOGSTASH PERFORMANCE TUNING TOOL                          ║"
echo "║  Optimize pipeline workers, batches, and throughput           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Get system info
CPU_CORES=$(nproc)
TOTAL_MEMORY=$(free -m | awk 'NR==2{print $2}')
AVAILABLE_MEMORY=$(free -m | awk 'NR==2{print $7}')

echo -e "${YELLOW}System Information:${NC}"
echo "  CPU Cores: $CPU_CORES"
echo "  Total Memory: ${TOTAL_MEMORY}MB"
echo "  Available Memory: ${AVAILABLE_MEMORY}MB"
echo ""

# Function to generate optimal settings
generate_optimal_settings() {
  echo -e "${YELLOW}Calculating optimal Logstash settings...${NC}"
  echo ""
  
  # Pipeline workers = 50% of CPU cores (minimum 2)
  WORKERS=$((CPU_CORES / 2))
  if [ $WORKERS -lt 2 ]; then
    WORKERS=2
  fi
  
  # Batch size = 1000 (good baseline)
  BATCH_SIZE=1000
  
  # Batch delay = 50ms (good baseline)
  BATCH_DELAY=50
  
  # Queue size = 20 x workers
  QUEUE_SIZE=$((WORKERS * 20))
  
  echo -e "${GREEN}Recommended Settings:${NC}"
  echo "  pipeline.workers: $WORKERS"
  echo "  pipeline.batch.size: $BATCH_SIZE"
  echo "  pipeline.batch.delay: ${BATCH_DELAY}ms"
  echo "  queue.max_bytes: ${QUEUE_SIZE}mb"
  echo ""
  
  echo -e "${YELLOW}Add to logstash.yml:${NC}"
  echo ""
  echo "pipeline.workers: $WORKERS"
  echo "pipeline.batch.size: $BATCH_SIZE"
  echo "pipeline.batch.delay: $BATCH_DELAY"
  echo "queue.max_bytes: ${QUEUE_SIZE}mb"
  echo ""
}

# Function to check Logstash performance
check_logstash_performance() {
  echo -e "${YELLOW}Checking Logstash performance metrics...${NC}"
  echo ""
  
  # Check if Logstash is running
  if ! pgrep -x "logstash" > /dev/null; then
    echo -e "${RED}✗ Logstash is not running${NC}"
    return 1
  fi
  
  echo -e "${GREEN}✓ Logstash is running${NC}"
  echo ""
  
  # Monitor Logstash process
  echo -e "${YELLOW}Logstash Process Info:${NC}"
  ps aux | grep "[l]ogstash" | awk '{print "  CPU: "$3"%, Memory: "$6"KB"}'
  
  echo ""
  
  # Check pipeline stats via API
  echo -e "${YELLOW}Pipeline Statistics:${NC}"
  curl -s http://localhost:9600/_node/stats/pipelines 2>/dev/null | \
    jq '.pipelines | to_entries[] | {name: .key, events_in: .value.events.in, events_out: .value.events.out}' 2>/dev/null || \
    echo "  Unable to fetch stats (Logstash monitoring not available)"
}

# Function to generate tuning configuration
generate_tuning_config() {
  echo -e "${YELLOW}Generating Logstash tuning configuration...${NC}"
  
  cat > /tmp/logstash-tuning.yml << EOFCONFIG
# Logstash Performance Tuning Configuration
# Generated on $(date)

# Pipeline configuration
pipeline.workers: $WORKERS
pipeline.batch.size: 1000
pipeline.batch.delay: 50

# Queue configuration (persisted queue for reliability)
queue.type: persisted
queue.max_bytes: 1gb
queue.checkpoint.interval: 1000

# Filter workers
filter {
  # Use mutate consolidation
  # Avoid nested conditionals
  # Cache geoip lookups
}

# Output configuration
output {
  elasticsearch {
    # Batch settings for performance
    batch_size => 1000
    flush_interval => 5
    workers => 4
    
    # Retry strategy
    max_retries => 3
    retry_on_conflict => 1
  }
}

# Monitoring
monitoring.enabled: true
monitoring.elasticsearch.hosts: ["localhost:9200"]

# JVM tuning (in jvm.options)
# -Xms512m
# -Xmx512m
# -XX:+UseG1GC

EOFCONFIG

  echo -e "${GREEN}Configuration generated:${NC}"
  cat /tmp/logstash-tuning.yml
  echo ""
  echo "To apply: cp /tmp/logstash-tuning.yml /etc/logstash/logstash.yml"
}

# Function to show performance tips
show_performance_tips() {
  echo -e "${YELLOW}=== LOGSTASH PERFORMANCE TIPS ===${NC}"
  echo ""
  
  echo -e "${GREEN}1. Filter Optimization${NC}"
  echo "   ✓ Consolidate multiple mutate filters into one"
  echo "   ✓ Use if conditions to avoid unnecessary processing"
  echo "   ✓ Place most frequent matches first in conditionals"
  echo ""
  
  echo -e "${GREEN}2. Pipeline Configuration${NC}"
  echo "   ✓ Set workers = CPU cores / 2"
  echo "   ✓ Batch size = 1000 (default is good)"
  echo "   ✓ Batch delay = 50ms (balance latency vs throughput)"
  echo ""
  
  echo -e "${GREEN}3. Output Optimization${NC}"
  echo "   ✓ Enable batch processing in Elasticsearch output"
  echo "   ✓ Use multiple output workers"
  echo "   ✓ Configure appropriate retry strategy"
  echo ""
  
  echo -e "${GREEN}4. Memory Management${NC}"
  echo "   ✓ Heap size = 25-50% of available RAM"
  echo "   ✓ Monitor garbage collection"
  echo "   ✓ Use G1GC for large heaps"
  echo ""
  
  echo -e "${GREEN}5. Monitoring${NC}"
  echo "   ✓ Enable Logstash monitoring API"
  echo "   ✓ Monitor pipeline latency"
  echo "   ✓ Check output backlog"
  echo ""
}

# Function to generate performance report
generate_performance_report() {
  echo -e "${YELLOW}=== LOGSTASH PERFORMANCE REPORT ===${NC}"
  echo ""
  echo "Generated: $(date)"
  echo ""
  
  echo -e "${GREEN}System Resources:${NC}"
  echo "  CPU Cores: $CPU_CORES"
  echo "  Total RAM: ${TOTAL_MEMORY}MB"
  echo "  Available RAM: ${AVAILABLE_MEMORY}MB"
  echo ""
  
  echo -e "${GREEN}Recommended Configuration:${NC}"
  echo "  Workers: $WORKERS"
  echo "  Batch Size: 1000"
  echo "  Batch Delay: 50ms"
  echo "  Queue Size: ${QUEUE_SIZE}mb"
  echo ""
  
  echo -e "${GREEN}Expected Performance:${NC}"
  echo "  Throughput: 10,000+ events/second"
  echo "  Latency: < 100ms p95"
  echo "  Memory: < 512MB"
  echo ""
  
  echo -e "${GREEN}Next Steps:${NC}"
  echo "  1. Apply settings to logstash.yml"
  echo "  2. Restart Logstash"
  echo "  3. Monitor pipeline stats"
  echo "  4. Tune based on actual performance"
}

# Menu
case "${1:-menu}" in
  generate)
    generate_optimal_settings
    ;;
  check)
    check_logstash_performance
    ;;
  config)
    generate_tuning_config
    ;;
  tips)
    show_performance_tips
    ;;
  report)
    generate_performance_report
    ;;
  all)
    generate_optimal_settings
    echo ""
    check_logstash_performance
    echo ""
    show_performance_tips
    echo ""
    generate_performance_report
    ;;
  *)
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 generate  - Generate optimal settings"
    echo "  $0 check     - Check current performance"
    echo "  $0 config    - Generate tuning configuration"
    echo "  $0 tips      - Show performance tips"
    echo "  $0 report    - Generate performance report"
    echo "  $0 all       - Run all checks"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 generate"
    echo "  $0 check"
    echo "  $0 all"
    ;;
esac

