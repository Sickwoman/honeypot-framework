#!/bin/bash

################################################################################
# Elasticsearch Optimization Script
# Optimizes indices, shards, and performance settings
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ELASTICSEARCH_URL="https://localhost:9200"
ELASTICSEARCH_USER="elastic"
ELASTICSEARCH_PASSWORD="${ELASTICSEARCH_PASSWORD:-changeme}"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  ⚡ ELASTICSEARCH OPTIMIZATION TOOL                            ║"
echo "║  Optimize indices, shards, and performance                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to check cluster health
check_health() {
  echo -e "${YELLOW}Checking cluster health...${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cluster/health?pretty" | \
    jq '.status, .active_shards, .unassigned_shards'
}

# Function to optimize indices
optimize_indices() {
  echo -e "${YELLOW}Optimizing indices...${NC}"
  
  # Get all indices
  INDICES=$(curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cat/indices?h=index" | grep honeypot)
  
  for index in $INDICES; do
    echo -e "  Optimizing ${GREEN}$index${NC}..."
    
    curl -s -X POST \
      -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
      -k "$ELASTICSEARCH_URL/$index/_forcemerge?max_num_segments=1" \
      -H 'Content-Type: application/json' > /dev/null
    
    echo -e "    ${GREEN}✓ Complete${NC}"
  done
}

# Function to apply ILM policy
apply_ilm_policy() {
  echo -e "${YELLOW}Creating ILM policy...${NC}"
  
  curl -s -X PUT \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_ilm/policy/honeypot-policy?pretty" \
    -H 'Content-Type: application/json' \
    -d '{
      "policy": "honeypot-policy",
      "phases": {
        "hot": {
          "min_age": "0d",
          "actions": {
            "rollover": {
              "max_primary_shard_size": "50GB",
              "max_age": "1d"
            }
          }
        },
        "warm": {
          "min_age": "7d",
          "actions": {
            "set_priority": {
              "priority": 50
            }
          }
        },
        "cold": {
          "min_age": "30d",
          "actions": {
            "set_priority": {
              "priority": 0
            }
          }
        },
        "delete": {
          "min_age": "90d",
          "actions": {
            "delete": {}
          }
        }
      }
    }' > /dev/null
  
  echo -e "${GREEN}✓ ILM policy created${NC}"
}

# Function to optimize shard allocation
optimize_shards() {
  echo -e "${YELLOW}Optimizing shard allocation...${NC}"
  
  # Set optimal shard count for honeypot indices
  curl -s -X PUT \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/honeypot-*/_settings?pretty" \
    -H 'Content-Type: application/json' \
    -d '{
      "settings": {
        "number_of_replicas": 0,
        "index.refresh_interval": "30s"
      }
    }' > /dev/null
  
  echo -e "${GREEN}✓ Shard optimization complete${NC}"
}

# Function to clear caches
clear_caches() {
  echo -e "${YELLOW}Clearing caches...${NC}"
  
  curl -s -X POST \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cache/clear?pretty" > /dev/null
  
  echo -e "${GREEN}✓ Caches cleared${NC}"
}

# Function to analyze performance
analyze_performance() {
  echo -e "${YELLOW}Analyzing performance metrics...${NC}"
  echo ""
  
  # Heap usage
  echo -e "${YELLOW}JVM Heap Usage:${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_nodes/stats/jvm?pretty" | \
    jq '.nodes[].jvm.mem | {heap_used_percent, heap_committed_in_bytes}' | head -10
  
  echo ""
  
  # Index stats
  echo -e "${YELLOW}Index Statistics:${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_stats?pretty" | \
    jq '.indices | {docs: .docs.count, size_in_bytes: .store.size_in_bytes, search_time_in_millis: .search.query_time_in_millis}'
  
  echo ""
  
  # Shard info
  echo -e "${YELLOW}Shard Distribution:${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cat/shards?v" | head -20
}

# Function to show optimization report
optimization_report() {
  echo -e "${YELLOW}=== OPTIMIZATION REPORT ===${NC}"
  echo ""
  
  echo -e "${GREEN}✓ Cluster Health${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cluster/health?pretty" | \
    jq '{status: .status, nodes: .number_of_nodes, active_shards: .active_shards}'
  
  echo ""
  echo -e "${GREEN}✓ Index Count${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cat/indices?h=index" | wc -l
  
  echo ""
  echo -e "${GREEN}✓ Total Documents${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cat/indices?h=docs.count" | \
    awk '{sum+=$1} END {print sum}'
  
  echo ""
  echo -e "${GREEN}✓ Total Storage${NC}"
  curl -s -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -k "$ELASTICSEARCH_URL/_cat/indices?h=store.size" | \
    awk '{gsub(/[a-z]/, ""); sum+=$1} END {print sum " bytes"}'
}

# Menu
case "${1:-menu}" in
  health)
    check_health
    ;;
  optimize)
    optimize_indices
    ;;
  ilm)
    apply_ilm_policy
    ;;
  shards)
    optimize_shards
    ;;
  cache)
    clear_caches
    ;;
  analyze)
    analyze_performance
    ;;
  report)
    optimization_report
    ;;
  all)
    check_health
    echo ""
    apply_ilm_policy
    echo ""
    optimize_shards
    echo ""
    clear_caches
    echo ""
    optimization_report
    ;;
  *)
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 health      - Check cluster health"
    echo "  $0 optimize    - Force merge all indices"
    echo "  $0 ilm         - Create ILM policy"
    echo "  $0 shards      - Optimize shard allocation"
    echo "  $0 cache       - Clear caches"
    echo "  $0 analyze     - Analyze performance"
    echo "  $0 report      - Show optimization report"
    echo "  $0 all         - Run all optimizations"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 health"
    echo "  $0 optimize"
    echo "  $0 all"
    ;;
esac

