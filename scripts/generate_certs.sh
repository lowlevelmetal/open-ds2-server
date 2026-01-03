#!/bin/bash
#
# Generate self-signed SSL certificates for Open DS2 Server
# These certificates are for testing purposes only.
#
# For connecting the real Dead Space 2 game client, you may need
# to configure the client to accept self-signed certificates or
# use certificates that match the original EA server names.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../certs"

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Certificate details
COUNTRY="US"
STATE="California"
CITY="Redwood City"
ORG="Open DS2 Server"
OU="Game Server"
CN="gosredirector.ea.com"  # Match the original EA redirector hostname

# Validity period (days)
DAYS=3650  # 10 years

echo "Generating SSL certificates for Open DS2 Server..."
echo "Certificate directory: $CERT_DIR"
echo ""

# Generate private key
echo "Generating private key..."
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate certificate signing request
echo "Generating certificate signing request..."
openssl req -new \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=$CN"

# Generate self-signed certificate
echo "Generating self-signed certificate..."
openssl x509 -req \
    -days $DAYS \
    -in "$CERT_DIR/server.csr" \
    -signkey "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt"

# Generate a combined PEM file (optional, for some servers)
cat "$CERT_DIR/server.crt" "$CERT_DIR/server.key" > "$CERT_DIR/server.pem"

# Clean up CSR (no longer needed)
rm "$CERT_DIR/server.csr"

# Set appropriate permissions
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"
chmod 600 "$CERT_DIR/server.pem"

echo ""
echo "SSL certificates generated successfully!"
echo ""
echo "Files created:"
echo "  $CERT_DIR/server.crt  - Certificate (public)"
echo "  $CERT_DIR/server.key  - Private key (keep secure!)"
echo "  $CERT_DIR/server.pem  - Combined cert+key"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -dates
echo ""
echo "NOTE: These are self-signed certificates for testing."
echo "The Dead Space 2 client may need patching to accept them,"
echo "or you may need to configure SSL certificate bypass."
