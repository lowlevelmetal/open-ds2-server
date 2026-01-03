# Open Dead Space 2 Server

🚀 **An open-source reconstruction of the Dead Space 2 multiplayer servers**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/std/the-standard)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()

---

## 💀 The Story

My buddy and I both love Dead Space 2. We wanted to play the multiplayer together on PC, only to find EA shut down the servers. We won't stand for it—so we're rebuilding them ourselves. *Make us whole again.*

---

## 🎯 Project Status

| Component | Status |
|-----------|--------|
| Protocol Reverse Engineering | ✅ Complete |
| TDF Serialization | ✅ Complete |
| Blaze Packet Codec | ✅ Complete |
| Redirector Service | ✅ Implemented |
| Authentication | ✅ Implemented |
| Game Manager | ✅ Implemented |
| Stats Service | ✅ Implemented |
| SSL/TLS Support | 🔄 In Progress |
| Full Game Testing | 📋 Planned |

---

## 🔧 Technical Architecture

### EA Blaze Protocol

Dead Space 2 uses **EA's Blaze** backend infrastructure—the same system powering Battlefield, Mass Effect 3, and other EA titles. Through reverse engineering the game binary, we've reconstructed the protocol:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT (Dead Space 2)                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ SSL/TLS (Port 42127)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    REDIRECTOR SERVICE                        │
│  • Responds to ServerInstanceRequest                         │
│  • Points client to game server                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ TCP (Port 10041)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    GAME SERVER                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │    Auth     │ │   Util      │ │   Stats     │            │
│  │  Component  │ │  Component  │ │  Component  │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   Game      │ │  Messaging  │ │  Association│            │
│  │  Manager    │ │  Component  │ │    Lists    │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

### Blaze Packet Structure

All communication uses a binary packet format with TDF (Type Definition Format) payloads:

```
┌────────┬────────┬────────┬────────┬────────┬────────┬─────────────┐
│ Length │ Comp   │ Cmd    │ Error  │ Msg    │ Msg    │   Payload   │
│ (2B)   │ ID(2B) │ ID(2B) │ (2B)   │ Type(2)│ ID(2B) │   (TDF)     │
└────────┴────────┴────────┴────────┴────────┴────────┴─────────────┘
   BE       BE       BE       BE       BE       BE      Variable
```

### TDF Encoding

TDF uses a tag-based binary serialization format:

| Type ID | Type | Description |
|---------|------|-------------|
| 0x00 | Integer | Variable-length encoded |
| 0x01 | String | Length-prefixed UTF-8 |
| 0x02 | Blob | Raw binary data |
| 0x03 | Struct | Nested TDF structure |
| 0x04 | List | Homogeneous array |
| 0x05 | Map | Key-value pairs |
| 0x06 | Union | Tagged union type |

Labels are encoded using a base-32 scheme compressed into 3 bytes.

### Component IDs

| Component | ID | Description |
|-----------|-----|-------------|
| Authentication | 0x01 | Login, personas, sessions |
| GameManager | 0x04 | Matchmaking, lobbies, games |
| Redirector | 0x05 | Initial connection routing |
| Stats | 0x07 | Player statistics, leaderboards |
| Util | 0x09 | Ping, config, telemetry |
| Messaging | 0x0F | In-game messaging |
| AssociationLists | 0x19 | Friends, blocked players |
| GameReporting | 0x1C | Post-match stats |

### Internal Codename: "Arson"

The game's internal codename is **Arson**, found throughout the binary in structures like:
- `ArsonCTF` - Capture the Flag mode
- `ArsonLeague` - Ranked/competitive play
- `ArsonClub` - Team/clan system

---

## 🚀 Building

### Prerequisites

- **Compiler**: GCC 9+ or Clang 10+ (C++17 required)
- **CMake**: 3.16 or higher
- **Platform**: Linux (Windows support planned)

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/lowlevelmetal/open-ds2-server.git
cd open-ds2-server

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make -j$(nproc)

# Binary located at build/bin/ds2-server
```

### Configuration

Edit `config/server.ini`:

```ini
[server]
bind_address = 0.0.0.0
game_port = 10041
redirector_port = 42127

[logging]
log_level = 1  # 0=Error, 1=Info, 2=Debug
```

---

## 🎮 Connecting

### Step 1: DNS Override

Add to your hosts file (`/etc/hosts` on Linux, `C:\Windows\System32\drivers\etc\hosts` on Windows):

```
YOUR_SERVER_IP    gosredirector.ea.com
YOUR_SERVER_IP    gosredirector.online.ea.com
```

### Step 2: Start the Server

```bash
./build/bin/ds2-server
```

### Step 3: Launch Dead Space 2

Start the game and attempt to connect to multiplayer. The client should connect to your server instead of EA's defunct servers.

> ⚠️ **Note**: SSL/TLS support is still in progress. You may need to bypass certificate validation or use a custom certificate.

---

## 🖥️ Client Setup Guide

Detailed instructions for connecting Dead Space 2 to your custom server.

### Windows Setup

#### 1. Edit Hosts File

1. Open Notepad **as Administrator** (right-click → Run as administrator)
2. Open the file: `C:\Windows\System32\drivers\etc\hosts`
3. Add these lines at the bottom (replace `SERVER_IP` with your server's IP address):

```
# Dead Space 2 Custom Server
SERVER_IP    gosredirector.ea.com
SERVER_IP    gosredirector.online.ea.com
```

4. Save the file

> **Example**: If your server is at `192.168.1.100`:
> ```
> 192.168.1.100    gosredirector.ea.com
> 192.168.1.100    gosredirector.online.ea.com
> ```

#### 2. Flush DNS Cache

Open Command Prompt as Administrator and run:
```cmd
ipconfig /flushdns
```

#### 3. Firewall Configuration

If running the server locally, ensure Windows Firewall allows:
- **TCP port 42127** (Redirector - SSL)
- **TCP port 10041** (Game server)

```cmd
netsh advfirewall firewall add rule name="DS2 Redirector" dir=in action=allow protocol=TCP localport=42127
netsh advfirewall firewall add rule name="DS2 Game Server" dir=in action=allow protocol=TCP localport=10041
```

#### 4. Launch Game

1. Start Dead Space 2 from Steam/Origin
2. Go to Multiplayer
3. The game will connect to your custom server

---

### Linux (Proton/Steam) Setup

#### 1. Edit Hosts File

```bash
sudo nano /etc/hosts
```

Add these lines (replace `SERVER_IP` with your server's IP):

```
# Dead Space 2 Custom Server
SERVER_IP    gosredirector.ea.com
SERVER_IP    gosredirector.online.ea.com
```

Save with `Ctrl+O`, exit with `Ctrl+X`.

#### 2. Flush DNS Cache

Depending on your distro:

```bash
# systemd-resolved (Ubuntu, Fedora, Arch, etc.)
sudo systemd-resolve --flush-caches

# Or restart the service
sudo systemctl restart systemd-resolved

# NetworkManager
sudo systemctl restart NetworkManager

# nscd (if installed)
sudo nscd -i hosts
```

#### 3. Steam Proton Configuration

Dead Space 2 runs well under Proton. Recommended settings:

1. In Steam, right-click **Dead Space 2** → **Properties**
2. Go to **Compatibility**
3. Check **Force the use of a specific Steam Play compatibility tool**
4. Select **Proton Experimental** or **Proton 8.0+**

#### 4. Launch Options (Optional)

For better debugging, you can add launch options:

1. Right-click Dead Space 2 → Properties → General
2. In **Launch Options**, add:
   ```
   PROTON_LOG=1 %command%
   ```

This creates logs in your home directory if you encounter issues.

#### 5. Firewall Configuration

If running the server on Linux:

```bash
# UFW (Ubuntu)
sudo ufw allow 42127/tcp comment "DS2 Redirector"
sudo ufw allow 10041/tcp comment "DS2 Game Server"

# firewalld (Fedora, RHEL)
sudo firewall-cmd --permanent --add-port=42127/tcp
sudo firewall-cmd --permanent --add-port=10041/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 42127 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 10041 -j ACCEPT
```

#### 6. Launch Game

Start Dead Space 2 from Steam and go to Multiplayer.

---

### Troubleshooting

#### Connection Refused / Timeout

1. **Verify hosts file**: Run `ping gosredirector.ea.com` - it should resolve to your server IP
2. **Check server is running**: Ensure you see "Server is running" in the server console
3. **Firewall**: Make sure ports 42127 and 10041 are open
4. **SSL Issues**: The game requires SSL on port 42127. Check server logs for SSL errors

#### DNS Not Updating

- Windows: Run `ipconfig /flushdns` and restart your browser/game
- Linux: Restart systemd-resolved or NetworkManager
- Try rebooting if DNS changes don't take effect

#### SSL Certificate Errors

The game validates SSL certificates. Current workarounds:

1. **Use the generated certificates** - Run `./scripts/generate_certs.sh` on the server
2. **Client patching** (advanced) - May be needed to bypass certificate validation

#### Game Crashes on Connect

- Check Proton version (try Proton Experimental)
- Verify game files in Steam
- Check server logs for protocol errors

#### "Server Unavailable" Message

This usually means the redirector responded but pointed to an unreachable game server. Verify:
- Game server port (10041) is accessible
- Server configuration has correct ports
- No firewall blocking between client and server

---

### Network Diagram

```
┌─────────────────┐         ┌─────────────────────────────────┐
│  Your Computer  │         │          Server                 │
│                 │         │                                 │
│  Dead Space 2   │◄───────►│  Port 42127 (SSL Redirector)   │
│   (Client)      │   SSL   │                                 │
│                 │         │  Port 10041 (Game Server)       │
│  hosts file:    │◄───────►│                                 │
│  gosredirector  │   TCP   │                                 │
│  .ea.com →      │         │                                 │
│  SERVER_IP      │         │                                 │
└─────────────────┘         └─────────────────────────────────┘
```

---

## 📁 Project Structure

```
open-ds2-server/
├── src/
│   ├── blaze/              # EA Blaze protocol implementation
│   │   ├── blaze_types.hpp # Enums, constants, structures
│   │   ├── tdf.hpp/cpp     # TDF serialization
│   │   ├── blaze_codec.hpp/cpp  # Packet encode/decode
│   │   ├── components.hpp/cpp   # Component handlers
│   │   └── blaze_server.hpp/cpp # Blaze server
│   ├── core/               # Server core
│   │   ├── server.hpp/cpp  # Main server class
│   │   ├── session.hpp/cpp # Client sessions
│   │   └── config.hpp/cpp  # Configuration
│   ├── network/            # Networking layer
│   │   ├── tcp_server.hpp/cpp
│   │   ├── udp_server.hpp/cpp
│   │   └── packet.hpp/cpp
│   ├── protocol/           # Legacy protocol handlers
│   ├── database/           # Data persistence
│   └── utils/              # Utilities (logging, crypto, buffers)
├── config/
│   └── server.ini          # Server configuration
├── docs/
│   └── PROTOCOL.md         # Protocol documentation
└── CMakeLists.txt
```

---

## 🔬 Reverse Engineering Notes

The protocol was reverse engineered from `deadspace2.exe` (32-bit PE, ~48MB) using:

- **Static Analysis**: Ghidra for disassembly and string extraction
- **String Mining**: Identified Blaze component names, server hostnames, TDF structure names
- **Cross-Reference**: Compared with other Blaze implementations (ME3, Battlefield)

Key discoveries:
- Server hostnames: `gosredirector.ea.com`, `gosredirector.online.ea.com`
- Ports: 42127 (SSL redirector), 7613 (alternate)
- Embedded root CA: Equifax Secure Certificate Authority

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for detailed protocol documentation.

---

## 🤝 Contributing

We need help with:

- **🔐 SSL/TLS Implementation**: Proper certificate handling for redirector
- **🧪 Testing**: Connecting actual game clients and fixing issues
- **📊 Game State**: Full synchronization of player positions, actions
- **💾 Persistence**: Database backend for stats and accounts
- **🪟 Windows Support**: Cross-platform networking code

### Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📚 Related Projects

- [Arcadia](https://github.com/jacobtread/Arcadia) - Mass Effect 3 Blaze server emulator
- [Battlefield Redux](https://github.com/BattlefieldRedux) - Battlefield server emulators
- [OpenSpy](https://github.com/openspy) - GameSpy server emulation

---

## ⚖️ Legal Notice

This project is not affiliated with, endorsed by, or connected to Electronic Arts Inc. or Visceral Games. Dead Space is a trademark of Electronic Arts Inc.

This is a clean-room reverse engineering project for educational and preservation purposes. No copyrighted code or assets from the original game are included.

---

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**"There's always Peng."**

*Built with frustration, nostalgia, and caffeine.*

</div>
