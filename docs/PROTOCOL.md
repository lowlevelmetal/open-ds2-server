# Dead Space 2 protocol notes

A working notebook. Most of the initial content is **borrowed from research on
other EA titles of the same era** (Mass Effect 3, Battlefield 3), which used
EA's Blaze 3 backend. Nothing here is confirmed for Dead Space 2 until it is
marked so.

Status legend: ✅ confirmed for DS2 · ❓ assumed from ME3/BF3 · ❌ known to differ

---

## 1. Expected connection flow ❓

1. The game resolves the **redirector** hostname (expected:
   `gosredirector.ea.com`) and connects, expected TCP port **42127**, probably
   over **SSLv3**.
2. It sends `Redirector::getServerInstance`. The reply gives the host/port of
   the **main Blaze server** and whether to use SSL there (`SECU`).
3. The game connects to the main server: `Util::preAuth` → login
   (`Authentication`) → `Util::postAuth` → presence, stats, matchmaking
   (`GameManager`), and so on.
4. Matches themselves were likely **player-hosted / peer-to-peer**, with Blaze
   only brokering host addresses. QoS/NAT probing may be a separate (UDP)
   service. Verify both.

## 2. First tasks

### 2a. Find out what the client actually contacts

- Capture while launching multiplayer (e.g. `tshark -i any -Y dns`) and
  record **every** hostname the game looks up.
- Point those names at your server in `/etc/hosts`. The game runs under
  Wine/Proton, which resolve names through Linux. The prefix's own
  `drive_c/windows/system32/drivers/etc/hosts` is not used.
- Run `opends2server` with `log_level = trace` and watch which port the client
  connects to (`tcp.flags.syn == 1` in Wireshark if nothing arrives).
- Look at the first bytes the client sends:
  - `16 03 00 ...` is an **SSLv3 ClientHello**. See 2b.
  - `16 03 01 ...` is a TLS 1.0 ClientHello.
  - Something that parses as a 12-byte Blaze header means plain TCP. Good news.

### 2b. SSL ❓

ME3-era clients used EA's ProtoSSL library: SSLv3 with RC4 cipher suites, and
certificate checks against an EA CA. Modern OpenSSL builds don't enable SSLv3
by default, and RC4 is deprecated, so a stock TLS stack likely won't
interoperate. Options:

- **Implement a minimal SSLv3 server** for the handful of cipher suites the
  client offers. The ME3 revival project PocketRelay took this route.
- **Patch or hook the client** (e.g. an ASI/DLL loader) to skip SSL or
  certificate verification.
- Certificate validation: ME3 projects got around the CA check. Find out how,
  and whether DS2's ProtoSSL build behaves the same way.

The transport plugs in at `net::Session`, which currently reads from a raw
`asio::ip::tcp::socket`. Wrap it in a stream abstraction when SSL lands.

### 2c. Framing and TDF

Implemented in `src/blaze/frame.*` and `src/blaze/tdf.*`. To check them against
real traffic, save the decrypted bytes as hex and run:

```sh
./build/debug/tools/tdfdump < captures/some-packet.hex
```

If decoding fails, the server logs a hex dump of the payload. That is your cue
that DS2's encoding differs (older Blaze versions used different TDF type IDs).

## 3. Recovering server responses

The official servers are gone, so you can only observe **client → server**
traffic. Ways to work out the replies:

- **Archived captures** from when the servers were live. Scrub credentials
  before sharing them.
- **The client binary.** Blaze client libraries often carry TDF reflection
  metadata (member names, tags, types) for every request/response class. In
  Ghidra, search for tag-like 4-letter upper-case strings near
  `getServerInstance`, `preAuth`, etc.
- **Other Blaze 3 titles' documented layouts** as a first guess.
- **Iterate:** send a guess and see what the client requests next, or where it
  stalls.

## 4. Component / command table

| Component | ID | Command | ID | Status | Notes |
|---|---|---|---|---|---|
| Redirector | 0x0005 | getServerInstance | 0x0001 | ❓ | Implemented (ME3 layout) |
| Util | 0x0009 | fetchClientConfig | 0x0001 | ❓ | |
| Util | 0x0009 | ping | 0x0002 | ❓ | Implemented (`STIM`) |
| Util | 0x0009 | preAuth | 0x0007 | ❓ | |
| Util | 0x0009 | postAuth | 0x0008 | ❓ | |
| Authentication | 0x0001 | | | ❓ | |
| GameManager | 0x0004 | | | ❓ | |
| Stats | 0x0007 | | | ❓ | |
| Messaging | 0x000F | | | ❓ | |
| AssociationLists | 0x0019 | | | ❓ | |
| GameReporting | 0x001C | | | ❓ | |
| UserSessions | 0x7802 | | | ❓ | |

## 5. Findings log

Add dated entries as things are confirmed or disproved.

```
### YYYY-MM-DD: <what you tested>
Setup:   game version, platform, how traffic was captured
Result:  what was observed (sanitized hex/tdfdump excerpt)
Impact:  which assumption above this confirms or breaks
```
