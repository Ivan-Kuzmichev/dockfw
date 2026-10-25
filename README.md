# dockfw

A per-container firewall for Docker, driven by labels. dockfw watches your
containers and installs an nftables table **inside each container's own
network namespace**, built from `fw.*` labels in your compose files. The host
firewall is never touched, nothing is persisted on the host, and the rules die
with the container.

It is built for the home-server case: a NAS running a dozen self-hosted apps
from other people's images, all on one Docker network, where you want to say
right in `compose.yml` who may talk to whom.

## Threat model

Assume one of your containers gets compromised (a vulnerable web app, a
malicious image update). Without dockfw it can reach your LAN, the NAS itself
and every neighbouring container. With dockfw a protected container can only
open connections you declared: to listed containers, to listed domains, to the
whole public internet, or to explicit CIDRs. Everything else, including private
ranges, is rejected. Inbound connections are dropped unless allowed by
`fw.inbound` or by a declared container-to-container link. dockfw does not
protect against containers that have `NET_ADMIN` or run privileged (they can
delete their own rules; dockfw warns about them), against attacks on the
kernel, or against a compromised Docker daemon.

## Quick start

```sh
docker network create fw
docker compose -f docker-compose.example.yml up -d
```

Put your apps on the `fw` network and label them:

```yaml
services:
  dublyarr:
    image: ghcr.io/ivan-kuzmichev/dublyarr:latest
    networks: [fw]
    ports: ["3030:3000"]
    labels:
      fw.enable: "true"
      fw.allow.containers: "qbittorrent,jackett"
      fw.allow.domains: "api.themoviedb.org,image.tmdb.org"
      fw.inbound: "192.168.1.0/24:3000"

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    networks: [fw]
    ports: ["8787:8787", "54890:54890", "54890:54890/udp"]
    labels:
      fw.enable: "true"
      fw.allow.internet: "true"
      fw.inbound: "192.168.1.0/24:8787,any:54890"

  vaultwarden:
    image: vaultwarden/server:latest
    networks: [fw]
    ports: ["8880:80"]
    labels:
      fw.enable: "true"
      fw.inbound: "192.168.1.0/24:80"

networks:
  fw: { external: true }
```

Vaultwarden can now only answer the LAN on port 80. qBittorrent can reach the
internet but not your LAN, and accepts the web UI from the LAN plus peers from
anywhere. dublyarr reaches qBittorrent, Jackett and TMDB, nothing else.

## Labels

All values are strings; lists are comma-separated, whitespace around items is
ignored. The prefix `fw.` is configurable (`FW_LABEL_PREFIX`).

| Label | Example | Meaning |
| --- | --- | --- |
| `fw.enable` | `true` | Protect this container. Without it dockfw leaves the container alone (unless `FW_UNLABELED=deny`). |
| `fw.allow.containers` | `qbittorrent, torrents/jackett` | Containers this one may connect to, all ports. A reference is a container name, a compose service, or `project/service`. |
| `fw.allow.domains` | `api.themoviedb.org, image.tmdb.org` | Public internet access limited to these domains (resolved to IPv4 addresses; private answers are dropped). |
| `fw.allow.internet` | `true` | The whole public internet. Private ranges stay closed. |
| `fw.allow.cidrs` | `192.168.1.5/32, 10.8.0.0/24` | Explicit exceptions, private ranges included (a printer, a VPN subnet). A bare address means `/32`. |
| `fw.inbound` | `192.168.1.0/24:8787, any:54890/udp` | Who may connect to this container: `<CIDR\|address\|any>:<port>[/tcp\|/udp]`. Without a protocol suffix both TCP and UDP are open. The port is the container port, not the published one. |
| `fw.mode` | `enforce` (default) or `audit` | `audit` logs and accepts instead of rejecting, to tune rules on live traffic. |

What the combinations give (outgoing):

- no `allow.*`: only loopback and replies to accepted inbound connections; the container is fully closed;
- `allow.containers`: plus those containers;
- `allow.domains`: plus the current addresses of those domains;
- `allow.internet: true`: everything except RFC 1918, CGNAT and link-local, but declared containers and CIDRs are still allowed.

**Symmetry.** If A has `fw.allow.containers: B`, dockfw also lets A in on B (all
ports). A link is declared once, on the initiator side. B cannot connect to A
unless it declares A itself.

**References** are resolved in this order: exact container name, then
`project/service` (compose labels), then a bare service name across all
projects. If a bare service name exists in more than one project the reference
is ambiguous and the container is locked; use `project/service`. All replicas
of a service match.

**Invalid labels lock the container.** A bad port, a malformed CIDR or domain,
an ambiguous reference or an unknown `fw.*` label (a typo such as
`fw.allow.domain`) never results in an open container: the container gets no
outbound access and no inbound except declared links from valid containers,
and dockfw logs an `error` naming the container and the label.

**Limitations of v1:**

- IPv6 is closed entirely, in both directions (except `any:` inbound rules).
- Wildcard domains (`*.tmdb.org`) are accepted but cannot be resolved: DNS
  cannot enumerate subdomains. List the exact names; dockfw logs a warning.
- Domains are allowed by IP. dockfw resolves them through the same Docker DNS
  the app uses, from inside the app's network namespace, and keeps every
  address for max(2×TTL, 5 min), but a CDN can still hand the app an address
  dockfw has not seen yet.
- dockfw applies rules a few milliseconds after a container starts. While
  dockfw is stopped, existing rules stay in place (fail-closed), but newly
  started containers run without rules until dockfw is back. Use
  `restart: unless-stopped`.
- Containers with `network_mode: host` or `container:<id>` are skipped with a
  warning. `network_mode: none` is skipped silently.

## Configuration

Environment variables only.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker API; `tcp://socket-proxy:2375` for a socket proxy. |
| `FW_LABEL_PREFIX` | `fw.` | Label prefix. |
| `FW_NETWORK` | `fw` | Docker network that `FW_UNLABELED` applies to. |
| `FW_UNLABELED` | `ignore` | `ignore`: leave unlabeled containers alone. `deny`: fully lock unlabeled containers attached to `FW_NETWORK`. |
| `FW_PRIVATE_RANGES` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,fc00::/7,fe80::/10` | What "not internet" means for `fw.allow.internet` and for filtering DNS answers. |
| `FW_RESOLVE_INTERVAL` | `60s` | How often domains are re-resolved. |
| `FW_RECONCILE_INTERVAL` | `30s` | How often tables are checked and restored. `0` disables it. |
| `FW_DOMAIN_TTL_MIN` | `5m` | Minimum lifetime of a resolved domain address. |
| `FW_LOG_LEVEL` | `info` | `debug` also prints every generated ruleset. |
| `FW_DRY_RUN` | `false` | Build policies and log the rulesets without applying them. Use it for the first run on a live server. |

## Running dockfw

dockfw needs `pid: host` (to find container namespaces), `SYS_ADMIN` (to enter
them), `NET_ADMIN` (to program nftables) and `SYS_PTRACE` (to open
`/proc/<pid>/ns/net` of processes owned by other users). It does not need a
network of its own (`network_mode: none`), runs from a read-only `FROM scratch`
image that contains only the static binary, and never enters the host network
namespace: the host's namespace (PID 1's) and its own are refused before any
`setns`. If all your containers run their PID 1 as root you can try dropping
`SYS_PTRACE`.

On hosts with AppArmor (Debian, Ubuntu) Docker's `docker-default` profile
does not let dockfw open the host's namespace, so dockfw logs a warning at
start and instead proves every namespace it touches is the container's own:
the namespace must hold the container's IP address (checked from
`/proc/<pid>/net/fib_trie`, without entering it) and the PID is re-checked with
Docker after the namespace is opened. The same profile also prevents dockfw
from opening containers that run with a different AppArmor profile
(`privileged`, `apparmor:unconfined`); those are reported as `degraded`.

### With the Docker socket

See [`docker-compose.example.yml`](docker-compose.example.yml).

### With a socket proxy

dockfw only needs to list, inspect and watch containers. To avoid handing it
the full Docker API, put [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
in front of the socket. dockfw then needs a network to reach the proxy; use an
`internal` one so it still has no route anywhere else:

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy:latest
    container_name: dockfw-socket-proxy
    restart: unless-stopped
    read_only: true
    tmpfs: [/run, /tmp]
    networks: [dockfw-api]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      CONTAINERS: 1
      EVENTS: 1
      PING: 1
      VERSION: 1
      POST: 0
      # everything else defaults to 0

  dockfw:
    image: ghcr.io/ivan-kuzmichev/dockfw:latest
    container_name: dockfw
    depends_on: [socket-proxy]
    pid: host
    networks: [dockfw-api]
    read_only: true
    restart: unless-stopped
    cap_drop: [ALL]
    cap_add: [NET_ADMIN, SYS_ADMIN, SYS_PTRACE]
    security_opt: ["no-new-privileges:true"]
    tmpfs: [/tmp]
    environment:
      DOCKER_HOST: tcp://dockfw-socket-proxy:2375
      FW_UNLABELED: deny
      FW_NETWORK: fw
    healthcheck:
      test: ["CMD", "/dockfw", "healthz"]
      interval: 30s
      start_period: 10s

networks:
  dockfw-api:
    internal: true
```

## Debugging

**See the rules of a container** from the host:

```sh
nsenter -t "$(docker inspect -f '{{.State.Pid}}' qbittorrent)" -n nft list table inet dockfw
```

The first output rule carries a `dockfw policy <hash>` comment; the hash also
appears in dockfw's logs. Reject rules have counters, so you can see what was
blocked.

**Logs** are JSON on stdout: `docker logs dockfw`. `info` = a policy was applied
(with counts of peers, domains, inbound rules), `warn` = something was skipped,
a DNS answer was dropped or a table had to be restored, `error` = invalid
labels or a failed nftables transaction. `FW_LOG_LEVEL=debug` prints every
generated policy and ruleset.

**Audit mode.** Set `fw.mode: audit` on a container to log instead of reject,
then watch the host kernel log:

```sh
sysctl -w net.netfilter.nf_log_all_netns=1   # log lines from container namespaces
dmesg -w | grep 'dockfw '
```

Each line is prefixed with `dockfw <container name>`. Switch back to `enforce`
when the rules are right.

**Dry run.** `FW_DRY_RUN=true` logs what would be applied without touching any
container.

**Something got blocked?** Check that both sides are on a shared network, that
the initiator lists the target in `fw.allow.containers`, and that the target has
no invalid labels (`docker logs dockfw | grep error`). Published ports need
`fw.inbound` with the *container* port. Connections from the host through a
published port may arrive from the Docker bridge gateway (for example
`172.18.0.1`) rather than from the client's address, depending on
`userland-proxy`.

## Verifying releases

Images are signed with cosign (keyless, GitHub OIDC):

```sh
cosign verify ghcr.io/ivan-kuzmichev/dockfw:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/Ivan-Kuzmichev/dockfw/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Static binaries for `linux/amd64` and `linux/arm64` with `checksums.txt` are
attached to every GitHub release.

## Development

```sh
make test         # unit tests (in a golang container on non-Linux hosts)
make lint         # go vet, staticcheck, golangci-lint
make integration  # end-to-end scenarios against the local Docker engine
make image        # build the image
```

Design notes and every deviation from the original specification are in
[`docs/NOTES.md`](docs/NOTES.md).
