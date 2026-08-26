# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email your findings to [INSERT SECURITY EMAIL]
3. Include detailed steps to reproduce the vulnerability
4. Allow up to 48 hours for an initial response

### What to Include

- Type of vulnerability
- Full paths of affected source files
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

### What to Expect

- Acknowledgment of your report within 48 hours
- Regular updates on our progress
- Credit in the security advisory (if desired)
- Notification when the issue is fixed

## Capability Decision: `CAP_NET_RAW` on the Installed Binary

**Status:** accepted design tradeoff (audit finding `F-SEC-001`, modernization task 4.6)

### What is granted

`install.sh` applies the Linux file capability `cap_net_raw+ep` to the installed
binary (`install.sh:405`, Phase 5):

```bash
sudo setcap 'cap_net_raw+ep' /usr/local/bin/mmtReader
```

- **Capability:** `CAP_NET_RAW` — permission to open raw and packet sockets
  (`AF_PACKET`), which includes placing interfaces in promiscuous mode.
- **Affected path:** `/usr/local/bin/mmtReader` by default. The path follows the
  installer's `PREFIX` (`${PREFIX}/bin/mmtReader`), so a custom install such as
  `sudo ./install.sh --prefix /opt/foo` grants the capability to
  `/opt/foo/bin/mmtReader` instead. The capability is only ever applied to the
  installed copy — a locally built `./mmtReader` never receives it.
- **`+ep` flags:** the capability is added to both the *permitted* and
  *effective* sets, meaning **every local user who executes the binary** gets
  raw-packet access through it — not just root or a dedicated group.

### Why it exists

Live capture needs raw-packet access, which the kernel reserves for privileged
processes. Without this capability every capture invocation would require
`sudo`. Granting the narrow `CAP_NET_RAW` capability instead of running the
whole program as root lets unprivileged users run:

```bash
mmtReader capture eth0 -a -s
```

while keeping all other root privileges unavailable to the process.

### Residual risk

Because the capability is file-based with `+ep`, any local account can use
`mmtReader` as a raw-packet tool. Concretely, this means any local user can:

- sniff all traffic visible on the host's network interfaces (including
  traffic not addressed to them),
- observe link-layer frames that would otherwise require root to read.

This is acceptable for single-operator workstations and analysis hosts where
all local users are already trusted with network visibility. It is **not**
appropriate for multi-user systems where packet capture must be restricted;
in that case remove the capability (below) and use one of the alternatives.

### Alternatives considered

| Alternative | Tradeoff |
|---|---|
| Run every capture with `sudo` | No standing capability, but each invocation needs an interactive root password or sudoers exception |
| Full `setuid root` binary | Grants far more than needed (entire root privilege set) — strictly worse than `cap_net_raw+ep`, rejected |
| File capabilities restricted to a group | Not supported by Linux file capabilities; group gating would require an ACL-wrapped wrapper, adding complexity out of proportion for this tool |

### How to remove the capability

For deployments that do not want the capability, drop it with:

```bash
sudo setcap -r /usr/local/bin/mmtReader
```

Notes:

- `./install.sh --uninstall` runs the same removal automatically before deleting
  the binary (`install.sh:166`).
- Removing the capability makes live capture fall back to requiring `sudo`;
  offline pcap analysis (`mmtReader -t file.pcap ...`) is unaffected.
- Re-running the installer re-applies the capability. Likewise, replacing or
  rebuilding the installed binary clears it (file capabilities do not survive
  file replacement); verify after upgrades.

### Verify current state

```bash
getcap /usr/local/bin/mmtReader        # prints the capability if set, silent if not
```

The installer performs the same check at the end of installation and prints the
manual `setcap` command if the capability could not be set (for example when
`sudo` lacks a TTY).

## Security Best Practices

When contributing to this project:

- Never commit secrets, API keys, or credentials
- Use environment variables for sensitive configuration
- Follow secure coding practices
- Report any security concerns immediately
