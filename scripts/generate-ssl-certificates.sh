#!/bin/bash

################################################################################
# SSL/TLS Certificate Generation for Honeypot Framework
# Generates self-signed certificates for Elasticsearch, Kibana, and Logstash
# Production: Replace with Let's Encrypt certificates
################################################################################

set -e

# Configuration
CERT_DIR="/etc/honeypot-framework/ssl"
CERT_VALIDITY_DAYS=365
COMMON_NAME="${1:-honeypot-framework.local}"
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORG="Honeypot Security Lab"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Create certificate directory
create_cert_dir() {
    log_info "Creating certificate directory: $CERT_DIR"
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    log_success "Certificate directory created"
}

# Generate CA certificate (Self-Signed)
generate_ca_cert() {
    log_info "Generating CA certificate..."
    
    if [[ -f "$CERT_DIR/ca-cert.pem" ]]; then
        log_warning "CA certificate already exists. Skipping..."
        return
    fi
    
    openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096
    
    openssl req -new -x509 -days $CERT_VALIDITY_DAYS \
        -key "$CERT_DIR/ca-key.pem" \
        -out "$CERT_DIR/ca-cert.pem" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$COMMON_NAME-CA"
    
    chmod 600 "$CERT_DIR/ca-key.pem"
    chmod 644 "$CERT_DIR/ca-cert.pem"
    
    log_success "CA certificate generated"
}

# Generate Elasticsearch certificates
generate_elasticsearch_certs() {
    log_info "Generating Elasticsearch certificates..."
    
    local ES_KEY="$CERT_DIR/elasticsearch-key.pem"
    local ES_CERT="$CERT_DIR/elasticsearch-cert.pem"
    local ES_CSR="$CERT_DIR/elasticsearch.csr"
    
    # Generate private key
    openssl genrsa -out "$ES_KEY" 4096
    
    # Create configuration file for Subject Alternative Names
    cat > "$CERT_DIR/elasticsearch.conf" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
CN = elasticsearch

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = elasticsearch
DNS.3 = elasticsearch.local
DNS.4 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

    # Generate CSR
    openssl req -new -key "$ES_KEY" \
        -out "$ES_CSR" \
        -config "$CERT_DIR/elasticsearch.conf"
    
    # Sign with CA
    openssl x509 -req -days $CERT_VALIDITY_DAYS \
        -in "$ES_CSR" \
        -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$ES_CERT" \
        -extensions v3_req \
        -extfile "$CERT_DIR/elasticsearch.conf"
    
    chmod 600 "$ES_KEY"
    chmod 644 "$ES_CERT"
    
    # Create PKCS12 format (required by Elasticsearch)
    openssl pkcs12 -export -in "$ES_CERT" -inkey "$ES_KEY" \
        -out "$CERT_DIR/elasticsearch.p12" \
        -name "elasticsearch" \
        -passout pass:changeme
    
    chmod 600 "$CERT_DIR/elasticsearch.p12"
    
    log_success "Elasticsearch certificates generated"
}

# Generate Kibana certificates
generate_kibana_certs() {
    log_info "Generating Kibana certificates..."
    
    local KIBANA_KEY="$CERT_DIR/kibana-key.pem"
    local KIBANA_CERT="$CERT_DIR/kibana-cert.pem"
    local KIBANA_CSR="$CERT_DIR/kibana.csr"
    
    # Generate private key
    openssl genrsa -out "$KIBANA_KEY" 4096
    
    # Create configuration file
    cat > "$CERT_DIR/kibana.conf" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
CN = kibana

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = kibana
DNS.3 = kibana.local
DNS.4 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

    # Generate CSR
    openssl req -new -key "$KIBANA_KEY" \
        -out "$KIBANA_CSR" \
        -config "$CERT_DIR/kibana.conf"
    
    # Sign with CA
    openssl x509 -req -days $CERT_VALIDITY_DAYS \
        -in "$KIBANA_CSR" \
        -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$KIBANA_CERT" \
        -extensions v3_req \
        -extfile "$CERT_DIR/kibana.conf"
    
    chmod 600 "$KIBANA_KEY"
    chmod 644 "$KIBANA_CERT"
    
    log_success "Kibana certificates generated"
}

# Generate Logstash certificates
generate_logstash_certs() {
    log_info "Generating Logstash certificates..."
    
    local LS_KEY="$CERT_DIR/logstash-key.pem"
    local LS_CERT="$CERT_DIR/logstash-cert.pem"
    local LS_CSR="$CERT_DIR/logstash.csr"
    
    # Generate private key
    openssl genrsa -out "$LS_KEY" 4096
    
    # Create configuration file
    cat > "$CERT_DIR/logstash.conf" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
CN = logstash

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = logstash
DNS.3 = logstash.local
DNS.4 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

    # Generate CSR
    openssl req -new -key "$LS_KEY" \
        -out "$LS_CSR" \
        -config "$CERT_DIR/logstash.conf"
    
    # Sign with CA
    openssl x509 -req -days $CERT_VALIDITY_DAYS \
        -in "$LS_CSR" \
        -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$LS_CERT" \
        -extensions v3_req \
        -extfile "$CERT_DIR/logstash.conf"
    
    chmod 600 "$LS_KEY"
    chmod 644 "$LS_CERT"
    
    log_success "Logstash certificates generated"
}

# Generate API certificates
generate_api_certs() {
    log_info "Generating API server certificates..."
    
    local API_KEY="$CERT_DIR/api-key.pem"
    local API_CERT="$CERT_DIR/api-cert.pem"
    local API_CSR="$CERT_DIR/api.csr"
    
    # Generate private key
    openssl genrsa -out "$API_KEY" 4096
    
    # Create configuration file
    cat > "$CERT_DIR/api.conf" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
CN = api

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = api
DNS.3 = api.local
DNS.4 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

    # Generate CSR
    openssl req -new -key "$API_KEY" \
        -out "$API_CSR" \
        -config "$CERT_DIR/api.conf"
    
    # Sign with CA
    openssl x509 -req -days $CERT_VALIDITY_DAYS \
        -in "$API_CSR" \
        -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$API_CERT" \
        -extensions v3_req \
        -extfile "$CERT_DIR/api.conf"
    
    chmod 600 "$API_KEY"
    chmod 644 "$API_CERT"
    
    log_success "API certificates generated"
}

# Set file permissions
set_permissions() {
    log_info "Setting certificate permissions..."
    
    # Make certs readable by specific services
    chown -R root:root "$CERT_DIR"
    chmod 755 "$CERT_DIR"
    chmod 600 "$CERT_DIR"/*.pem
    chmod 600 "$CERT_DIR"/*.p12
    chmod 644 "$CERT_DIR"/*-cert.pem
    chmod 644 "$CERT_DIR"/ca-cert.pem
    
    log_success "Permissions set correctly"
}

# Display summary
display_summary() {
    log_info "Certificate generation completed!"
    echo ""
    echo "=========================================="
    echo "Certificate Summary"
    echo "=========================================="
    echo "Certificate Directory: $CERT_DIR"
    echo "Validity: $CERT_VALIDITY_DAYS days"
    echo ""
    echo "Generated Certificates:"
    ls -lh "$CERT_DIR"/*.pem 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
    echo ""
    echo "=========================================="
    echo "Next Steps:"
    echo "=========================================="
    echo "1. Update Elasticsearch config:"
    echo "   - xpack.security.http.ssl.key: $CERT_DIR/elasticsearch-key.pem"
    echo "   - xpack.security.http.ssl.certificate: $CERT_DIR/elasticsearch-cert.pem"
    echo ""
    echo "2. Update Kibana config:"
    echo "   - server.ssl.enabled: true"
    echo "   - server.ssl.certificate: $CERT_DIR/kibana-cert.pem"
    echo "   - server.ssl.key: $CERT_DIR/kibana-key.pem"
    echo ""
    echo "3. Update Logstash config:"
    echo "   - output elasticsearch {"
    echo "       ssl_certificate_verification => true"
    echo "       cacert => \"$CERT_DIR/ca-cert.pem\""
    echo "     }"
    echo ""
    echo "4. Import CA certificate on clients:"
    echo "   - cp $CERT_DIR/ca-cert.pem /usr/local/share/ca-certificates/"
    echo "   - update-ca-certificates"
    echo ""
    echo "=========================================="
}

# Cleanup temporary files
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.conf "$CERT_DIR"/*.srl
    log_success "Cleanup completed"
}

# Main execution
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  🔐 Honeypot Framework - SSL/TLS Certificate Generator       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    check_root
    create_cert_dir
    generate_ca_cert
    generate_elasticsearch_certs
    generate_kibana_certs
    generate_logstash_certs
    generate_api_certs
    set_permissions
    cleanup
    display_summary
    
    echo ""
    log_success "All done! Certificates are ready for use."
}

# Run main function
main
