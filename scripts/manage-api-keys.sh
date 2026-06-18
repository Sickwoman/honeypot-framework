#!/bin/bash

################################################################################
# API Key Management Script
# Manages Elasticsearch and Kibana API keys for secure access
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
echo "║  🔑 API KEY MANAGEMENT TOOL                                   ║"
echo "║  Manage Elasticsearch and Kibana API keys securely            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Functions
create_api_key() {
  local KEY_NAME="$1"
  local ROLE="${2:-viewer}"
  
  echo -e "${YELLOW}Creating API key: $KEY_NAME${NC}"
  
  RESPONSE=$(curl -s -X POST \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    -H "Content-Type: application/json" \
    "$ELASTICSEARCH_URL/_security/api_key" \
    -d "{
      \"name\": \"$KEY_NAME\",
      \"role_descriptors\": {
        \"honeypot-role\": {
          \"cluster\": [\"monitor\"],
          \"index\": [
            {
              \"names\": [\"honeypot-*\"],
              \"privileges\": [\"read\", \"view_index_metadata\"]
            }
          ]
        }
      },
      \"expiration\": \"90d\"
    }" 2>/dev/null)
  
  API_ID=$(echo $RESPONSE | jq -r '.id')
  API_KEY=$(echo $RESPONSE | jq -r '.api_key')
  
  if [ "$API_ID" != "null" ]; then
    echo -e "${GREEN}✓ API Key Created${NC}"
    echo ""
    echo "Key ID: $API_ID"
    echo "API Key: $API_KEY"
    echo "Encoded: $(echo -n "$API_ID:$API_KEY" | base64)"
    echo ""
    echo "⚠️  Save this key securely - you won't see it again!"
    echo ""
  else
    echo -e "${RED}✗ Failed to create API key${NC}"
    echo "Response: $RESPONSE"
  fi
}

list_api_keys() {
  echo -e "${YELLOW}Listing API keys...${NC}"
  echo ""
  
  curl -s -X GET \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    "$ELASTICSEARCH_URL/_security/api_key" | \
    jq '.api_keys[] | {id: .id, name: .name, creation: .creation, expiration: .expiration, enabled: .active}' 2>/dev/null || \
    echo -e "${RED}Failed to list API keys${NC}"
}

delete_api_key() {
  local KEY_ID="$1"
  
  if [ -z "$KEY_ID" ]; then
    echo -e "${RED}Error: API Key ID required${NC}"
    return 1
  fi
  
  echo -e "${YELLOW}Deleting API key: $KEY_ID${NC}"
  
  RESPONSE=$(curl -s -X DELETE \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    "$ELASTICSEARCH_URL/_security/api_key" \
    -H "Content-Type: application/json" \
    -d "{\"ids\": [\"$KEY_ID\"]}" 2>/dev/null)
  
  if echo $RESPONSE | grep -q "invalidated"; then
    echo -e "${GREEN}✓ API Key Deleted${NC}"
  else
    echo -e "${RED}✗ Failed to delete API key${NC}"
  fi
}

invalidate_expired_keys() {
  echo -e "${YELLOW}Invalidating expired API keys...${NC}"
  
  curl -s -X DELETE \
    -u $ELASTICSEARCH_USER:$ELASTICSEARCH_PASSWORD \
    "$ELASTICSEARCH_URL/_security/api_key" \
    -H "Content-Type: application/json" \
    -d '{"expire_time": "now-1d"}' 2>/dev/null || \
    echo -e "${RED}Failed to invalidate expired keys${NC}"
}

grant_access() {
  local KEY_NAME="$1"
  local USER="$2"
  
  echo -e "${YELLOW}Granting access: $KEY_NAME → $USER${NC}"
  
  # Create API key tied to user
  create_api_key "$KEY_NAME-$USER"
}

# Menu
case "${1:-menu}" in
  create)
    if [ -z "$2" ]; then
      echo "Usage: $0 create <key-name>"
      exit 1
    fi
    create_api_key "$2"
    ;;
  list)
    list_api_keys
    ;;
  delete)
    if [ -z "$2" ]; then
      echo "Usage: $0 delete <key-id>"
      exit 1
    fi
    delete_api_key "$2"
    ;;
  invalidate)
    invalidate_expired_keys
    ;;
  grant)
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo "Usage: $0 grant <key-name> <user>"
      exit 1
    fi
    grant_access "$2" "$3"
    ;;
  *)
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 create <key-name>        - Create new API key"
    echo "  $0 list                     - List all API keys"
    echo "  $0 delete <key-id>          - Delete API key"
    echo "  $0 invalidate               - Invalidate expired keys"
    echo "  $0 grant <name> <user>      - Grant access to user"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 create logstash-key"
    echo "  $0 list"
    echo "  $0 delete S1Z6T4bQTwqP7d4XgfcR5A"
    echo "  $0 grant kibana-access team-member"
    ;;
esac

