# Dead Space 2 Server Emulator

A C++ server emulator for Dead Space 2 multiplayer, implementing the EA Blaze protocol.

## Overview

This server emulates the EA Blaze infrastructure that Dead Space 2 uses for multiplayer:

- **Redirector Server** (port 42127): Initial connection point that redirects clients to the main server
- **Blaze Server** (port 10041): Main game server handling authentication, matchmaking, and game sessions
- **QoS Server** (port 17502): HTTP server for NAT detection and quality of service

## Building

### Prerequisites

- CMake 3.16+
- C++17 compatible compiler (GCC 8+, Clang 7+)
- Perl (for OpenSSL build)
- Git (for submodules)

**Note:** OpenSSL 1.1.1 is automatically downloaded and built as part of the CMake process. This bundled version provides native TLS 1.0 support required for Dead Space 2 compatibility.

### Install Build Dependencies

**Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake perl git
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake perl git
```

**Fedora:**
```bash
sudo dnf install gcc gcc-c++ cmake perl git make
```

**macOS (Homebrew):**
```bash
brew install cmake perl
```

### Build Steps

```bash
# Initialize submodules (if not already done)
git submodule update --init --recursive

# Create build directory
mkdir build && cd build

# Configure (this will download and build OpenSSL 1.1.1)
cmake ..

# Build (first build takes longer due to OpenSSL compilation)
make -j$(nproc)
```

The first build will take several minutes as it downloads and compiles OpenSSL 1.1.1w. Subsequent builds will be faster.

## SSL Certificates

The server requires SSL certificates for the Blaze protocol connections.

### Generate Self-Signed Certificates

Use the bundled OpenSSL to generate certificates:

```bash
# Create certs directory
mkdir -p certs

# Use the bundled OpenSSL from the build
OPENSSL=./build/openssl/install/bin/openssl

# If bundled OpenSSL isn't available yet, use system openssl:
# OPENSSL=openssl

# Generate private key
$OPENSSL genrsa -out certs/server.key 2048

# Generate self-signed certificate
$OPENSSL req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
    -subj "/CN=gosredirector.online.ea.com"
```

For the game to accept the certificates, you may need to:
1. Add the certificate to your system's trusted certificates
2. Or patch the game to skip certificate verification

## Running

```bash
# Run with default settings
./build/ds2-server

# Run with custom config
./build/ds2-server --config server.cfg
```

## Configuration

Create a `server.cfg` file:

```ini
# Server addresses
redirector_host = 0.0.0.0
redirector_port = 42127

blaze_host = 0.0.0.0
blaze_port = 10041

qos_host = 0.0.0.0
qos_port = 17502

# SSL certificates
ssl_cert = certs/server.crt
ssl_key = certs/server.key
```

## Connecting the Game

To connect Dead Space 2 to this server, you need to redirect the game's DNS queries:

### Option 1: Hosts File

Add to `/etc/hosts` (Linux/macOS) or `C:\Windows\System32\drivers\etc\hosts` (Windows):

```
127.0.0.1 gosredirector.online.ea.com
127.0.0.1 ds2prod.online.ea.com
```

### Option 2: Local DNS Server

Run a local DNS server that redirects EA hostnames to your server IP.

## Protocol Overview

### Blaze Protocol

The Blaze protocol uses:
- 12-byte packet headers (length, component, command, error, type, message ID)
- TDF (Tag Data Format) encoding for payload data
- SSL/TLS encryption

### Components

| Component | ID | Description |
|-----------|-----|-------------|
| Authentication | 0x01 | Login, sessions |
| GameManager | 0x04 | Game sessions, matchmaking |
| Redirector | 0x05 | Server redirection |
| Stats | 0x07 | Statistics |
| Util | 0x09 | Ping, configuration |
| Association | 0x19 | Friend lists |
| Playgroups | 0x1E | Party management |

### Connection Flow

1. Client connects to Redirector (42127)
2. Redirector returns Blaze server address
3. Client connects to Blaze server (10041)
4. PreAuth → Authentication → PostAuth
5. Ready for matchmaking/games

## Development Status

- [x] Redirector component
- [x] Authentication (basic)
- [x] Util component
- [x] GameManager (basic)
- [x] QoS server
- [ ] Full matchmaking
- [ ] Game state synchronization
- [ ] Stats tracking
- [ ] Friend lists

## License

This project is for educational and preservation purposes only.

## References

- [docs/04-blaze-connection-analysis.md](../docs/04-blaze-connection-analysis.md) - Protocol analysis
- [BlazeSDK documentation](../docs/03-main-executable-analysis.md) - SDK structure
