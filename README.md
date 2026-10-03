# opends2server

A community server for **Dead Space 2** multiplayer, written in C++23. The goal is
to keep the game's online modes playable now that EA's official servers are
offline.

> **Status: skeleton.** The networking core, Blaze packet framing, the TDF codec
> and two example handlers work. Nothing has been tested against the real game
> yet. Start with [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Building

Requirements: CMake ≥ 3.25, Ninja, and a C++23 compiler with `std::format`
(developed with GCC 16). If Asio and GoogleTest aren't installed system-wide,
they are downloaded automatically.

```sh
cmake --preset debug          # or: release, asan
cmake --build --preset debug
ctest --preset debug
```

## Running

```sh
cp config/server.example.ini config/server.ini
./build/debug/src/opends2server --config config/server.ini
```

The game runs under Wine/Proton, which resolve names through Linux. To point
it at the server, add the redirector hostname to `/etc/hosts` on the machine
running the game (the hostname is an assumption; confirm it, see
`docs/PROTOCOL.md`):

```
<server-ip>  gosredirector.ea.com
```

The game probably wraps the redirector connection in SSLv3, which isn't
implemented yet, so expect the handshake to fail until that's solved.

## Layout

```
src/
  core/       logging, config, hex dumps, big-endian byte reader/writer
  blaze/      Blaze frame codec, TDF codec, component IDs, request router
  net/        per-connection Session (Asio coroutines, ordered write queue)
  server/     listeners + dispatch from frames to router
  services/   one file per Blaze component: request handlers live here
  main.cpp
tools/
  tdfdump     decode hex-encoded Blaze frames / TDF payloads for RE work
tests/        GoogleTest unit tests
docs/         protocol research notes
config/       example configuration
```

## Adding a handler

Handlers are registered per component in `src/services/`:

```cpp
router.add(blaze::component::Util, blaze::util::PreAuth, "preAuth",
           [&config](blaze::RequestContext& ctx) {
               // Request fields are available via ctx.body.find("TAG").
               // The reply layout below is illustrative only.
               tdf::Writer w;
               w.string("SVER", "opends2server")
                   .begin_group("CONF")
                   .integer("PORT", config.blaze_port)
                   .end_group();
               return blaze::Reply{.payload = w.take()};
           });
```

Tags such as `"ASRC"` are checked at compile time: lower-case or over-long
labels won't build. Requests with no registered handler are logged with their
decoded TDF body and get an empty reply, so you can see exactly what the client
asks for next.

## Reverse-engineering workflow

1. Run with `log_level = trace` to log every payload as a hex dump and a decoded TDF tree.
2. Save interesting bytes as hex and inspect them offline:
   ```sh
   ./build/debug/tools/tdfdump < captures/packet.hex        # whole frames
   ./build/debug/tools/tdfdump --raw < captures/body.hex    # payload only
   ```
3. Record confirmed facts in `docs/PROTOCOL.md`.

## Ground rules

- Clean-room only: don't commit EA code, game binaries or assets.
- Packet captures can contain account emails, passwords and tokens. `captures/`
  and `*.pcap*` are git-ignored; share sanitized excerpts only.
