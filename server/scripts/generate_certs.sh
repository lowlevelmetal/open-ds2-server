#!/bin/bash
# Generate self-signed SSL certificates for DS2 server
# Uses the bundled OpenSSL 1.1.1 built by CMake

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$SERVER_DIR/certs"
DAYS=365

# Use bundled OpenSSL from build directory
BUNDLED_OPENSSL="$SERVER_DIR/build/openssl/install/bin/openssl"
BUNDLED_OPENSSL_DIR="$SERVER_DIR/build/openssl/install"

if [ -x "$BUNDLED_OPENSSL" ]; then
    OPENSSL="$BUNDLED_OPENSSL"
    # Unset OPENSSL_CONF to avoid needing openssl.cnf
    unset OPENSSL_CONF
    echo "Using bundled OpenSSL: $OPENSSL"
    $OPENSSL version
else
    echo "Bundled OpenSSL not found at: $BUNDLED_OPENSSL"
    echo "Please build the server first: cd build && cmake .. && make"
    echo ""
    echo "Falling back to system OpenSSL..."
    OPENSSL="openssl"
    $OPENSSL version
    echo ""
    echo "WARNING: System OpenSSL may not support TLS 1.0 required by Dead Space 2"
fi

# Create certs directory
mkdir -p "$CERT_DIR"

echo ""
echo "Generating SSL certificates for Dead Space 2 Server..."
echo ""

# Generate CA key and certificate (self-signed, no config needed)
# Use SHA-1 for maximum compatibility with 2010-era OpenSSL clients
echo "Creating CA..."
$OPENSSL genrsa -out "$CERT_DIR/ca.key" 4096
$OPENSSL req -new -x509 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" -days $DAYS \
    -subj "/C=US/ST=California/L=Redwood City/O=Electronic Arts/CN=EA Blaze CA" \
    -sha1 \
    -batch

# Generate server key
echo "Creating server key..."
$OPENSSL genrsa -out "$CERT_DIR/server.key" 2048

# Create server certificate request (minimal, no config file needed)
echo "Creating certificate request..."
$OPENSSL req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=California/L=Redwood City/O=Electronic Arts/OU=EA Online/CN=gosredirector.online.ea.com" \
    -sha1 \
    -batch

# Sign server certificate with CA (using command-line extensions instead of config file)
# Use SHA-1 for maximum compatibility with 2010-era clients
echo "Signing server certificate..."
$OPENSSL x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt" -days $DAYS \
    -sha1 \
    -extfile <(printf "subjectAltName=DNS:gosredirector.online.ea.com,DNS:ds2prod.online.ea.com,DNS:ds2.online.ea.com,DNS:localhost,IP:127.0.0.1")

# Combine certificate chain
cat "$CERT_DIR/server.crt" "$CERT_DIR/ca.crt" > "$CERT_DIR/server_chain.crt"

# Clean up temporary files
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

echo ""
echo "Certificates generated in $CERT_DIR/"
echo ""
echo "Files created:"
echo "  $CERT_DIR/ca.key             - CA private key"
echo "  $CERT_DIR/ca.crt             - CA certificate (install in system to trust)"
echo "  $CERT_DIR/server.key         - Server private key"
echo "  $CERT_DIR/server.crt         - Server certificate"
echo "  $CERT_DIR/server_chain.crt   - Full certificate chain"
echo ""
echo "To trust the CA on your system:"
echo ""
echo "  Linux (Arch/general):"
echo "    sudo trust anchor --store $CERT_DIR/ca.crt"
echo ""
echo "  Linux (Ubuntu/Debian):"
echo "    sudo cp $CERT_DIR/ca.crt /usr/local/share/ca-certificates/ea-blaze-ca.crt"
echo "    sudo update-ca-certificates"
echo ""
echo "  macOS:"
echo "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_DIR/ca.crt"
echo ""
echo "  Windows:"
echo "    certutil -addstore -f \"ROOT\" $CERT_DIR\\ca.crt"
echo ""
echo "  Windows:"
echo "    certutil -addstore -f \"ROOT\" $CERT_DIR/ca.crt"
