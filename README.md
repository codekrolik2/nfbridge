# nfbridge

`nfbridge` is a thin Linux packet interceptor built on
[NFQUEUE](https://netfilter.org/projects/libnetfilter_queue/). It makes **no policy
decisions**. For every packet that netfilter puts on its queue it:

1. receives the packet (id, metadata and payload) from the kernel,
2. sends it to a **Java decision process** over a Unix domain socket,
3. waits synchronously for the Java verdict (`ALLOW` or `DROP`),
4. returns the verdict to the kernel (`NF_ACCEPT` / `NF_DROP`).

If the Java process is unavailable, slow or misbehaves, a configurable
**fail-closed** (default, drop) or **fail-open** (accept) verdict is applied and the
connection is re-established automatically.

```
 kernel netfilter ──NFQUEUE──▶ nfbridge (C) ──Unix socket──▶ Java decision process
        ▲                         │   ▲                              │
        └──── NF_ACCEPT/NF_DROP ──┘   └──────── ALLOW / DROP ────────┘
```

## Layout

```
include/nfbridge/   public headers (config, log, protocol, ipc, nfq)
src/main.c          entry point, signal handling, exit codes
src/config.c        command-line parsing
src/nfq.c           NFQUEUE setup, receive loop, per-packet callback, verdicts
src/ipc.c           Unix socket client: framing, timeouts, reconnect/backoff
src/protocol.c      binary wire format encode/decode/validation
src/log.c           leveled logging to stderr
tools/mock_responder.c  stand-in for the Java side, for manual testing
tests/              unit tests (protocol) and IPC tests against fake servers
```

## Build

Prerequisites (Debian/Ubuntu):

```sh
sudo apt-get install build-essential cmake pkg-config libnetfilter-queue-dev libmnl-dev
```

Fedora/RHEL: `sudo dnf install gcc cmake pkgconf-pkg-config libnetfilter_queue-devel libmnl-devel`

Build, test and install:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure   # or: (cd build && ctest)
sudo cmake --install build                   # installs /usr/local/sbin/nfbridge
```

CMake options: `-DNFBRIDGE_WERROR=ON` (warnings as errors), `-DNFBRIDGE_BUILD_TOOLS=OFF`
(skip the mock responder), `-DBUILD_TESTING=OFF` (skip tests).

### Releases

`.github/workflows/release.yml` runs when a `v*` tag is pushed. The tag must match the
`VERSION` in `CMakeLists.txt` (tags with a suffix such as `v0.2.0-rc1` become
pre-releases). It builds with `-DNFBRIDGE_WERROR=ON`, runs the tests on Ubuntu 22.04
(x86_64 and aarch64) and publishes a GitHub release with
`nfbridge-<tag>-linux-<arch>.tar.gz` (`nfbridge`, `nfbridge-mock-responder`, README,
LICENSE) and `SHA256SUMS`:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The binaries link dynamically against `libnetfilter_queue`; install it on the target
(`sudo apt-get install libnetfilter-queue1` / `sudo dnf install libnetfilter_queue`).

## Run

```
nfbridge [-q NUM] [-s PATH] [-t MS] [--fail-open] [-l LEVEL | -v]

  -q, --queue NUM        NFQUEUE number to bind (0-65535, default 0)
  -s, --socket PATH      Unix socket of the Java process (default /run/nfbridge/nfbridge.sock)
  -t, --timeout-ms MS    max time to wait for a verdict (default 1000)
  -o, --fail-open        ACCEPT packets when Java is unavailable (default: DROP)
  -l, --log-level LEVEL  error, warn, info or debug (default info)
  -v, --verbose          shortcut for --log-level debug
```

Example:

```sh
sudo ./build/nfbridge --queue 0 --socket /run/nfbridge/nfbridge.sock --timeout-ms 500
```

Logs go to stderr. Exit codes: `0` clean shutdown (SIGINT/SIGTERM), `1` fatal runtime
error (e.g. cannot open/bind the queue, missing privileges), `2` invalid arguments.

The Java process is the **server**: it creates and listens on the Unix socket; `nfbridge`
connects to it. `nfbridge` may be started before Java – it keeps retrying (exponential
backoff 100 ms → 5 s) and applies the fail policy verdict meanwhile.

### Routing traffic to the queue (kill switch, recommended)

The intended deployment is a **kill switch**: a packet passes only if the whole approval
chain (kernel → `nfbridge` → Java) explicitly approves it. If any link is missing or
broken, the packet is not approved and is **dropped**:

| Failure                                                        | Result  | Enforced by                                 |
|----------------------------------------------------------------|---------|---------------------------------------------|
| `nfbridge` not running / crashed / not bound to the queue      | DROP    | kernel – queue rule has **no** `bypass`     |
| Java not running, socket missing, connection lost              | DROP    | `nfbridge` fail-closed default              |
| Java too slow (`--timeout-ms` exceeded) or malformed reply     | DROP    | `nfbridge` fail-closed default              |
| Kernel queue full (packets arrive faster than verdicts)        | DROP    | kernel – `--fail-open` not set              |
| Java answers `DROP`                                            | DROP    | Java policy                                 |
| Java answers `ALLOW`                                           | ACCEPT  | – the only path to ACCEPT                   |

Requirements for this to hold:

- The queue rule must **not** use `--queue-bypass` (iptables) / `bypass` (nftables).
- `nfbridge` must run **without** `--fail-open`.
- Nothing is exempted from approval – not loopback, not the Java process. An accepted
  loopback path would let a compromised process drive another local process (proxy, agent,
  daemon) whose outbound traffic Java does approve, laundering its traffic through it.
  Loopback packets traverse both OUTPUT and INPUT, so Java sees them twice; local services
  that use loopback (e.g. a DNS stub resolver on `127.0.0.53`) stop working whenever the
  chain is down, by design.
- The examples below include loopback and SSH (port 22) exemptions **commented out**. Both
  are unapproved paths; uncomment them only if you knowingly accept that (e.g. SSH as a
  temporary lockout safety net during setup).
- No exemption is needed for the `nfbridge` ↔ Java link: it is a Unix domain socket,
  which never passes through netfilter. The Java decision process should not need network
  access of its own; if it does, that traffic is queued like any other and – because
  verdicts are synchronous – would stall waiting on itself, so design the decision
  process to work without it.

**Lockout warning:** with these rules active and `nfbridge`/Java not running, all queued
traffic is dropped – that is the point. Keep console access while testing.

iptables:

```sh
# Everything goes to the queue. The commented-out exemptions are unapproved paths –
# uncomment only if you accept that risk.
# sudo iptables -A INPUT  -i lo -j ACCEPT
# sudo iptables -A INPUT  -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT  -j NFQUEUE --queue-num 0
# sudo iptables -A OUTPUT -o lo -j ACCEPT
# sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0

# Repeat with ip6tables for IPv6 (or drop IPv6 entirely), otherwise IPv6 bypasses the switch
```

nftables:

```sh
sudo nft add table inet nfbridge
sudo nft add chain inet nfbridge in  '{ type filter hook input   priority 0; policy drop; }'
sudo nft add chain inet nfbridge out '{ type filter hook output  priority 0; policy drop; }'
sudo nft add chain inet nfbridge fwd '{ type filter hook forward priority 0; policy drop; }'
# Commented-out exemptions are unapproved paths – uncomment only if you accept that risk.
# sudo nft add rule inet nfbridge in  iif lo accept
# sudo nft add rule inet nfbridge in  tcp dport 22 accept
sudo nft add rule inet nfbridge in  queue num 0
# sudo nft add rule inet nfbridge out oif lo accept
# sudo nft add rule inet nfbridge out tcp sport 22 accept
sudo nft add rule inet nfbridge out queue num 0
sudo nft add rule inet nfbridge fwd queue num 0
# Remove everything again (this switches the kill switch off)
sudo nft delete table inet nfbridge
```

The `inet` table covers IPv4 and IPv6. `policy drop` on the chains is a second safety net:
a packet that somehow does not reach the queue rule is still dropped rather than accepted.

Run `nfbridge` without `--fail-open`:

```sh
sudo ./build/nfbridge --queue 0 --socket /run/nfbridge/nfbridge.sock --timeout-ms 500
```

Quick verification of the kill switch (from a non-excluded path, e.g. `ping 1.1.1.1`):

1. rules active, `nfbridge` stopped → traffic blocked (kernel drops, no listener);
2. `nfbridge` running, Java stopped → traffic blocked (fail-closed verdict);
3. `nfbridge` and Java running, Java answers ALLOW → traffic passes.

### Alternative: fail-open / bypass setup (not a kill switch)

If availability matters more than enforcement, the chain can be configured to let traffic
through when it is broken. **This is not a kill switch** – with `nfbridge` or Java down,
traffic flows unfiltered.

- `--queue-bypass` / `bypass` on the rule: the kernel ACCEPTs packets while no `nfbridge`
  is bound to the queue.
- `nfbridge --fail-open`: ACCEPT when Java is unavailable/slow/misbehaving, and on kernel
  queue overflow.

iptables (start narrow – a catch-all rule with a broken consumer cuts off the host,
including your SSH session):

```sh
# Only ICMP to/from this host
sudo iptables -I INPUT  -p icmp -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0 --queue-bypass

# Forwarded traffic
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# IPv6 equivalent
sudo ip6tables -I OUTPUT -p ipv6-icmp -j NFQUEUE --queue-num 0 --queue-bypass
```

nftables:

```sh
sudo nft add table inet nfbridge
sudo nft add chain inet nfbridge in  '{ type filter hook input  priority 0; policy accept; }'
sudo nft add chain inet nfbridge out '{ type filter hook output priority 0; policy accept; }'
# Keep loopback and the SSH session out of the queue, send the rest to queue 0
sudo nft add rule inet nfbridge in  iif lo accept
sudo nft add rule inet nfbridge in  tcp dport 22 accept
sudo nft add rule inet nfbridge in  queue num 0 bypass
sudo nft add rule inet nfbridge out oif lo accept
sudo nft add rule inet nfbridge out tcp sport 22 accept
sudo nft add rule inet nfbridge out queue num 0 bypass
# Remove everything again
sudo nft delete table inet nfbridge
```

```sh
sudo ./build/nfbridge --queue 0 --socket /run/nfbridge/nfbridge.sock --fail-open
```

If the Java process itself talks over the network, its traffic can stall waiting on its own
verdicts. In this fail-open setup it may be excluded by uid (`meta skuid` /
`-m owner --uid-owner`) or by mark; in the kill-switch setup such an exemption would be an
unapproved path and is not used.

### Manual testing with the mock responder

```sh
# terminal 1: stand-in for Java (modes: allow, drop, alternate, drop-icmp; optional --delay-ms)
./build/nfbridge-mock-responder --socket /tmp/nfbridge.sock --mode drop-icmp

# terminal 2
sudo ./build/nfbridge --queue 7 --socket /tmp/nfbridge.sock -v

# terminal 3
sudo iptables -I OUTPUT -o lo -p icmp -j NFQUEUE --queue-num 7
ping -c1 127.0.0.1          # dropped by the mock
sudo iptables -D OUTPUT -o lo -p icmp -j NFQUEUE --queue-num 7
```

## IPC protocol

A single persistent `SOCK_STREAM` Unix-domain connection, initiated by `nfbridge`.
Strictly request/response: exactly one request is outstanding at a time and the next
request is only sent after its response arrives. All integers are **big-endian**
(Java's `DataInputStream`/`ByteBuffer` default).

**Request** (`nfbridge` → Java): 40-byte header followed by `payload_len` bytes.

| Offset | Size | Field            | Notes                                              |
|-------:|-----:|------------------|----------------------------------------------------|
| 0      | 4    | `magic`          | `0x4E464252` (`"NFBR"`)                            |
| 4      | 2    | `version`        | `1`                                                |
| 6      | 2    | `type`           | `1` = REQUEST                                      |
| 8      | 8    | `correlation_id` | unsigned, increases per request; echo it back      |
| 16     | 4    | `packet_id`      | NFQUEUE packet id (informational)                  |
| 20     | 2    | `hw_protocol`    | EtherType: `0x0800` IPv4, `0x86DD` IPv6            |
| 22     | 1    | `hook`           | netfilter hook: 0 PREROUTING, 1 INPUT, 2 FORWARD, 3 OUTPUT, 4 POSTROUTING |
| 23     | 1    | `flags`          | reserved, always `0`                               |
| 24     | 4    | `mark`           | packet mark                                        |
| 28     | 4    | `indev`          | input interface index, `0` if none                 |
| 32     | 4    | `outdev`         | output interface index, `0` if none                |
| 36     | 4    | `payload_len`    | `0..65535`                                         |
| 40     | N    | `payload`        | packet bytes starting at the IP header             |

**Response** (Java → `nfbridge`): fixed 20 bytes.

| Offset | Size | Field            | Notes                              |
|-------:|-----:|------------------|------------------------------------|
| 0      | 4    | `magic`          | `0x4E464252`                       |
| 4      | 2    | `version`        | `1`                                |
| 6      | 2    | `type`           | `2` = RESPONSE                     |
| 8      | 8    | `correlation_id` | must equal the request's value     |
| 16     | 4    | `decision`       | `1` = ALLOW, `2` = DROP            |

Error handling in `nfbridge`: partial reads/writes are handled transparently. A response
with a wrong magic/version/type/decision or a mismatched `correlation_id`, an EOF, an I/O
error or a timeout (`--timeout-ms`, covering send + receive) causes `nfbridge` to apply the
fail policy verdict to that packet and **close the connection** (so a late or garbage reply
can never be matched to a later packet), then reconnect. If a send fails with
`EPIPE`/`ECONNRESET` on a connection that went stale while idle, the request is resent once
on a fresh connection.

Minimal Java server loop (Java 16+ Unix sockets):

```java
var server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
server.bind(UnixDomainSocketAddress.of("/run/nfbridge/nfbridge.sock"));
while (true) {
    try (SocketChannel ch = server.accept();
         var in = new DataInputStream(new BufferedInputStream(Channels.newInputStream(ch)));
         var out = new DataOutputStream(new BufferedOutputStream(Channels.newOutputStream(ch)))) {
        while (true) {
            if (in.readInt() != 0x4E464252 || in.readUnsignedShort() != 1 || in.readUnsignedShort() != 1)
                throw new IOException("bad request");
            long corr = in.readLong();
            int packetId = in.readInt();
            int hwProto = in.readUnsignedShort();
            int hook = in.readUnsignedByte();
            in.readUnsignedByte();               // flags
            int mark = in.readInt(), indev = in.readInt(), outdev = in.readInt();
            int len = in.readInt();
            if (len < 0 || len > 65535) throw new IOException("bad length");
            byte[] packet = in.readNBytes(len);

            boolean allow = decide(packet);      // your policy

            out.writeInt(0x4E464252);
            out.writeShort(1);
            out.writeShort(2);
            out.writeLong(corr);
            out.writeInt(allow ? 1 : 2);
            out.flush();
        }
    } catch (EOFException e) { /* nfbridge disconnected; accept the next connection */ }
}
```

## Security and operational caveats

- **Privileges.** NFQUEUE requires root or `CAP_NET_ADMIN`. Prefer running unprivileged with
  only that capability, e.g. systemd `User=nfbridge`, `AmbientCapabilities=CAP_NET_ADMIN`,
  `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges=yes`.
- **Socket trust.** Whoever listens on the socket path decides the fate of every queued
  packet and receives full packet contents. Put the socket in a directory only the Java
  service user can write (e.g. `/run/nfbridge`, mode `0750`), and restrict who can connect.
- **Fail-closed vs fail-open.** The recommended setup is the
  [kill switch](#routing-traffic-to-the-queue-kill-switch-recommended): if any part of the
  approval chain is down, slow or misbehaving, packets are not approved and are
  **dropped** – a Java or `nfbridge` outage becomes a network outage for queued traffic, by
  design. Two independent settings control this: the rule's `--queue-bypass` / `bypass`
  (what the kernel does when **no** `nfbridge` is bound – without it, drop) and
  `nfbridge --fail-open` (what `nfbridge` does when Java is unavailable, and whether the
  kernel accepts on queue overflow via `NFQA_CFG_F_FAIL_OPEN` – without it, drop). Using
  either one gives up the kill-switch guarantee.
- **Lockout.** Test rules on a narrow match first and keep console access or an excluded
  management (SSH) session while doing so. In the kill-switch setup every other exemption
  is an unapproved path – do not add one.
- **Throughput.** This version is intentionally synchronous: one packet in flight at a time,
  so throughput is bounded by the Java round-trip latency. A stuck Java process stalls the
  queue for up to `--timeout-ms` per packet. Packets are copied up to 65535 bytes.
- **IPv6.** Both AF_INET and AF_INET6 are bound; on modern kernels (≥ 3.8) this is a no-op and
  the queue receives whatever your iptables/ip6tables/nftables rules send to it.

## Code style and linting

- C11, compiled with `-Wall -Wextra -Wshadow -Wformat=2 -Wconversion ...`; CI-style check:
  `cmake -S . -B build -DNFBRIDGE_WERROR=ON && cmake --build build`.
- Formatting is defined in `.clang-format` (LLVM base, 4-space indent, 100 columns):
  ```sh
  clang-format -i src/*.c include/nfbridge/*.h tools/*.c tests/*.c        # format
  clang-format --dry-run --Werror src/*.c include/nfbridge/*.h tools/*.c tests/*.c  # check
  ```
- Optional static analysis: `clang-tidy -p build src/*.c` (uses `build/compile_commands.json`)
  or `cppcheck --enable=warning,performance --project=build/compile_commands.json`.

## License

Apache License 2.0 – see [LICENSE](LICENSE).
