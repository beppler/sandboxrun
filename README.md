# sandboxrun

Run a command inside a container that can only reach the hosts you explicitly
allow. `sandboxrun` starts an allowlisting HTTP/HTTPS forward proxy on the
host, then launches the container with no direct network access — only a path
to that proxy.

## Usage

```sh
sandboxrun -allow google.com -allow "*.google.com" -image alpine -- wget -q -S -O /dev/null google.com
```

### Flags

| Flag | Description |
| ---- | ----------- |
| `-allow HOST` | Allowed host, repeatable: exact (`api.github.com`) or wildcard (`*.example.com`). Omit entirely for no network access at all |
| `-port PORT` | Allowed destination port, repeatable (default: 80, 443) |
| `-runtime NAME` | `podman` (Linux, default) \| `apple` (macOS) \| `wslc` (Windows/WSL) |
| `-image IMG` | Container image |
| `-name NAME` | Optional container name, passed to the runtime as `--name` |
| `-helper PATH` | Path to a Linux build of `sandboxinit` (podman, wslc). Default: `sandboxinit-linux-<arch>` next to the `sandboxrun` binary |
| `-volume HOST:CTR[:rw]` | Mount a host path into the container, repeatable; default read-only, add `:rw` for read-write |
| `-it` | Interactive TTY |
| `-proxy ADDR` | wslc: address the container uses to reach the host proxy (default: `host.wslc.internal`) |
| `-bind ADDR` | wslc: host address the proxy binds to (default `0.0.0.0`, see the security note below) |
| `-uid` / `-gid` | wslc: user the workload runs as inside the container (default 1000) |
| `-log DEST` | Proxy log: empty = off, `-` = stderr, otherwise a file path |

## How it works

Two layers of defence in the proxy:

1. **Policy**: hostname allowlist + port allowlist.
2. **SSRF protection**: a dialer control hook refuses loopback, private and
   link-local destinations *after* DNS resolution, so an allowed hostname can
   never be used to reach the host itself or the LAN (DNS rebinding).

### Runtimes

- **podman** (Linux): container has no network; `sandboxinit relay` forwards
  TCP to the proxy over a Unix socket.
- **apple** (macOS): container runs on a host-only network; the proxy listens
  on the network gateway.
- **wslc** (Windows): proxy binds on the host; `sandboxinit guard` runs the
  workload in an empty network namespace (no `nft` needed in the image; the container gets `SYS_ADMIN`+`NET_ADMIN`, dropped before the workload runs) and drops privileges to `-uid`/`-gid`.

### Security note: wslc proxy binding

On Windows the default `-bind 0.0.0.0` is deliberate: the container reaches the
host through the WSL virtual network's gateway address, which is only known at
runtime (binding to loopback would break the container). That means the proxy
also accepts connections from other machines on your LAN; the host allowlist is
the only gate. To limit exposure, add a Windows Firewall inbound rule for the
proxy port restricted to the WSL subnet, or pass `-bind` with the host's
WSL-side address (`wsl.exe -- ip route show default` prints it as the "via"
address).

## Building

```sh
make helpers   # static Linux sandboxinit for amd64/arm64 into dist/
make hosts     # sandboxrun for linux/darwin/windows into dist/
```

## Using engine and proxy from other Go packages

Both packages are importable from other modules:

```go
import (
    "go.beppler.dev.br/sandboxrun/engine"
    "go.beppler.dev.br/sandboxrun/proxy"
)
```

- `engine.ForName("podman"|"apple"|"wslc")` returns a runtime that turns an
  `engine.Spec` into an `engine.Plan` (command line + listener).
- `proxy.New(proxy.Config{Allow: ..., Ports: ...})` returns the allowlisting
  proxy server.
