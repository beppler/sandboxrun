# sandboxrun

Run a command inside a container that can only reach the hosts you explicitly
allow. `sandboxrun` starts an allowlisting HTTP/HTTPS forward proxy on the
host, then launches the container with no direct network access — only a path
to that proxy.

Supported hosts: Linux, macOS and Windows only.

## Usage

```sh
sandboxrun -allow google.com -allow "*.google.com" -image alpine -- wget -q -S -O /dev/null google.com
```

### Flags

| Flag | Description |
| ---- | ----------- |
| `-allow HOST` | Allowed host, repeatable: exact (`api.github.com`) or wildcard (`*.example.com`). Omit entirely for no network access at all |
| `-port PORT` | Allowed destination port, repeatable (default: 80, 443) |
| `-image IMG` | Container image |
| `-name NAME` | Optional container name, passed to the runtime as `--name` |
| `-helper PATH` | Path to a Linux build of `sandboxinit` (podman, wslc). Default: `sandboxinit-linux-<arch>` next to the `sandboxrun` binary |
| `-volume HOST:CTR[:rw]` | Mount a host path into the container, repeatable; default read-only, add `:rw` for read-write |
| `-it` | Interactive TTY |
| `-uid` / `-gid` | wslc: user the workload runs as inside the container (default 1000) |
| `-log DEST` | Proxy log: empty = off, `-` = stderr, otherwise a file path |

## How it works

Two layers of defence in the proxy:

1. **Policy**: hostname allowlist + port allowlist.
2. **SSRF protection**: a dialer control hook refuses loopback, private and
   link-local destinations *after* DNS resolution, so an allowed hostname can
   never be used to reach the host itself or the LAN (DNS rebinding).

### Runtimes

Chosen automatically by OS.

- **podman** (Linux): container has no network; `sandboxinit relay` forwards
  TCP to the proxy over a Unix socket.
- **apple** (macOS): container runs on a host-only network; the proxy listens
  on the network gateway.
- **wslc** (Windows): proxy binds on the host's loopback (`127.0.0.1`); the
  workload runs in an empty network namespace as `-uid`/`-gid`.

## Building

```sh
make helpers   # static Linux sandboxinit for amd64/arm64 into dist/
make hosts     # sandboxrun for linux/darwin/windows into dist/
```
