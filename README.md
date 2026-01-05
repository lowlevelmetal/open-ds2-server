# Dead Space 2 Multiplayer Server

An open-source server emulator for Dead Space 2 (PC, 2011) multiplayer, implementing EA's proprietary Blaze protocol.

> **Project Goal**: Restore online multiplayer functionality for Dead Space 2 after EA's official servers were shut down.

## 🎮 Features

- **Full Blaze Protocol** - Custom C++ implementation of EA's BlazeSDK server
- **TDF Encoding** - Complete Tag Data Format encoder/decoder
- **SSL/TLS Support** - Secure connections matching original infrastructure  
- **Multiple Server Components**:
  - Redirector Server (port 42127) - Initial connection routing
  - Blaze Server (port 10041) - Authentication, matchmaking, game sessions
  - QoS Server (port 17502) - Network quality detection

### Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Redirector | ✅ Complete | Server instance routing |
| Authentication | ✅ Complete | Login, silent login, Origin login |
| Util | ✅ Complete | Pre/post auth, client config |
| GameManager | 🔄 In Progress | Create/join/list games |
| Matchmaking | 🔄 In Progress | Queue-based matching |
| Association | ⏳ Planned | Friends lists |
| Stats | ⏳ Planned | Leaderboards |

---

## 🚀 Quick Start

### Prerequisites

- **C++ Compiler**: GCC 8+ or Clang 7+ (C++17 support)
- **CMake**: 3.16+
- **Perl**: Required for OpenSSL build
- **Dead Space 2**: Steam or Origin version

> **Note**: OpenSSL 1.1.1 is automatically downloaded and built during the CMake process. This bundled version provides native TLS 1.0 support required for Dead Space 2 (2011) compatibility.

### Building

```bash
# Clone the repository
git clone https://github.com/yourname/ds2-server.git
cd ds2-server

# Initialize dependencies
cd server
git submodule update --init --recursive

# Build (first build downloads and compiles OpenSSL 1.1.1)
mkdir build && cd build
cmake ..
make -j$(nproc)
```

⏱️ **First build takes ~5 minutes** due to OpenSSL compilation. Subsequent builds are fast.

### Generating SSL Certificates

```bash
cd server
mkdir -p certs

# Generate private key and certificate
openssl genrsa -out certs/server.key 2048
openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
    -subj "/CN=gosredirector.online.ea.com"
```

### Running the Server

```bash
cd server
./build/ds2-server
```

You should see:
```
[INFO] Dead Space 2 Server Emulator starting...
[INFO] SSL configured with bundled OpenSSL 1.1.1
[INFO] TLS versions enabled: TLS 1.0, TLS 1.1, TLS 1.2
[INFO] Redirector listening on port 42127
[INFO] Blaze server listening on port 10041
[INFO] QoS server listening on port 17502
```

### Connecting Your Game

Add these entries to your hosts file:

**Linux/macOS**: `/etc/hosts`  
**Windows**: `C:\Windows\System32\drivers\etc\hosts`

```
127.0.0.1 gosredirector.online.ea.com
127.0.0.1 ds2prod.online.ea.com
```

Launch Dead Space 2 and select Multiplayer!

---

## 📁 Project Structure

```
ds2-server/
├── server/                       # 🎯 Main server implementation
│   ├── CMakeLists.txt            # Build configuration (downloads OpenSSL 1.1.1)
│   ├── README.md                 # Server-specific documentation
│   ├── extern/                   # Git submodule dependencies
│   │   ├── asio/                 # Standalone networking library
│   │   └── spdlog/               # High-performance logging
│   ├── include/
│   │   ├── blaze/                # Protocol implementation
│   │   │   ├── types.hpp         # Core types and enums
│   │   │   ├── packet.hpp        # Packet encoding/decoding
│   │   │   ├── tdf.hpp           # Tag Data Format
│   │   │   └── component.hpp     # Component base class
│   │   ├── network/              # Network layer
│   │   │   ├── ssl_server.hpp    # SSL/TLS server
│   │   │   ├── client_connection.hpp
│   │   │   └── qos_server.hpp    # HTTP QoS endpoints
│   │   └── components/           # Blaze components
│   │       ├── redirector.hpp    # Server routing
│   │       ├── authentication.hpp
│   │       ├── util.hpp
│   │       └── game_manager.hpp
│   └── src/                      # Implementation files
│
├── docs/                         # 📚 Protocol documentation
│   ├── README.md                 # Documentation index
│   └── 04-blaze-connection-analysis.md  # Connection flow analysis
│
├── scripts/                      # 🔧 Utility tools (Python)
│   ├── memory_dumper.py          # Binary analysis tools
│   └── find_process.py           # Process utilities
│
└── research/                     # 🔬 Reverse engineering notes
    └── REVERSE_ENGINEERING_NOTES.md
```

---

## 🔧 Configuration

The server uses sensible defaults but can be configured:

| Setting | Default | Description |
|---------|---------|-------------|
| Redirector Port | 42127 | Initial connection point |
| Blaze Port | 10041 | Main game server |
| QoS Port | 17502 | Network quality endpoints |
| SSL Certs | `certs/` | Certificate directory |

---

## 📖 Protocol Documentation

This project includes extensive reverse engineering documentation:

| Document | Description |
|----------|-------------|
| [Blaze Connection Flow](docs/04-blaze-connection-analysis.md) | Complete connection sequence |
| [Server Documentation](server/README.md) | Implementation details |
| [RE Notes](REVERSE_ENGINEERING_NOTES.md) | Raw research notes |

### EA Blaze Protocol Overview

The Blaze protocol uses:
- **TDF (Tag Data Format)**: Binary serialization with 3-byte compressed tags
- **Components**: Modular RPC system (Auth, GameManager, Util, etc.)
- **SSL/TLS**: All traffic encrypted
- **Async messaging**: Request/response with notifications

```
Client                          Server
  |                               |
  |----[SSL Handshake]----------->|
  |                               |
  |----[preAuth request]--------->|
  |<---[preAuth response]---------|
  |                               |
  |----[login request]----------->|
  |<---[login response]-----------|
  |                               |
  |----[postAuth request]-------->|
  |<---[postAuth response]--------|
  |                               |
  |----[Game operations...]------>|
```

---

## 🔬 Research & Reverse Engineering

This project was built through extensive reverse engineering of Dead Space 2's binaries.

### Tools Used
- **Ghidra** - Static analysis and decompilation
- **x64dbg** - Dynamic analysis under Wine
- **Custom Python scripts** - Memory dumping and binary analysis

### Key Discoveries
- 453 BlazeSDK classes identified in executable
- 164 Blaze error codes documented  
- Complete connection state machine mapped
- TDF encoding scheme fully reversed

### RE Documentation

| Document | Description |
|----------|-------------|
| [Solidshield Unpacking](docs/01-solidshield-unpacking.md) | DRM layer analysis |
| [Binary Analysis](docs/02-activation-dll-analysis.md) | Function mapping |
| [Executable Analysis](docs/03-main-executable-analysis.md) | PE structure, classes |
| [Blaze Protocol](docs/04-blaze-connection-analysis.md) | Network protocol |

---

## 🤝 Contributing

Contributions welcome! Areas that need work:

- [ ] Complete matchmaking queue logic
- [ ] Stats/leaderboard component
- [ ] Association (friends) component  
- [ ] Game state relay between clients
- [ ] Traffic capture for protocol accuracy
- [ ] Persistent storage backend
- [ ] Docker containerization

### Development Setup

```bash
# Build with debug symbols
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

# Run with verbose logging
./ds2-server --verbose
```

---

## 📜 Legal

This project is for **educational and preservation purposes only**.

- Reverse engineering conducted for interoperability under applicable law
- No copyrighted game assets included
- Server implementation is clean-room based on protocol observations
- Original game required to play

**Dead Space 2** is a trademark of Electronic Arts Inc.

---

## 🙏 Acknowledgments

- The Dead Space community for keeping the game alive
- EA/Visceral Games for creating Dead Space 2
- Open-source projects: Asio, spdlog, OpenSSL

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| Lines of C++ | ~3,500 |
| Blaze components | 4 implemented |
| Protocol commands | 15+ |
| Documentation | ~130 KB |

---

*Reverse engineering analysis conducted 2024-2026*
