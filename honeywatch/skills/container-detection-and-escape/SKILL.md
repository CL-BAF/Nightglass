---
name: container-detection-and-escape
description: Detect container environments and escape via Docker socket, privileged mode, or kernel exploits
domain: cybersecurity
subdomain: container-security
tags: [docker, container, escape, privileged, docker-socket]
version: '1.0'
nist_csf: [PR.AA-01]
mitre_attack: [T1611]
---

## When to use

After gaining a foothold — check if you're inside a container and whether
escape to the host is possible. The loot phase checks for `.dockerenv`,
`/proc/1/cgroup` patterns, and `/var/run/docker.sock`.

## Detection signals

- `.dockerenv` file exists in root → container
- `/proc/1/cgroup` contains `docker`, `containerd`, `kubepods` → container
- `/var/run/docker.sock` exists → Docker socket mounted (escape possible)
- `capsh --print` shows extra capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE)

## Escape vectors

1. **Docker socket** — mount the host filesystem in a new container:
   `docker run --rm -v /:/hostfs alpine chroot /hostfs sh`
   Gives full host root. Use the `privesc_docker_escape` payload.

2. **Privileged container** — if the container was started with `--privileged`:
   - Mount the host disk directly: `mount /dev/sda1 /mnt`
   - Access host devices: `mknod /dev/sda...`
   - Use `nsenter` to enter the host's PID namespace

3. **Kernel exploit** — containers share the host kernel. Dirty Pipe (CVE-2022-0847)
   works from inside a container because it's a kernel-level bug.

## Post-escape

After escaping, you have host root. Pivot to adjacent subnets, grab
`/etc/shadow`, and deploy persistence on the host (not the container).