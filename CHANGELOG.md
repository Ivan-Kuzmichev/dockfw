# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/): patch = fixes without changing
labels or rules, minor = new labels or env options (backwards compatible),
major = changed semantics of existing labels or defaults.

## [Unreleased]

### Added

- Daemon that applies nftables rules inside container network namespaces
  based on `fw.*` labels: `fw.enable`, `fw.allow.containers`,
  `fw.allow.domains`, `fw.allow.internet`, `fw.allow.cidrs`, `fw.inbound`,
  `fw.mode`.
- Symmetric inbound access for declared container-to-container connections.
- Domain allowlists resolved from inside the container netns with TTL-based
  expiry; private answers are dropped.
- Reconcile loop that restores deleted or modified tables.
- `FW_UNLABELED=deny` to lock down unlabeled containers on the fw network.
- `fw.mode: audit` (log instead of reject) and `FW_DRY_RUN`.
- `dockfw healthz` heartbeat check, `dockfw --version`.
- Multi-arch `FROM scratch` image, CI, signed releases.
