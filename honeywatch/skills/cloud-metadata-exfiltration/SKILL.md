---
name: cloud-metadata-exfiltration
description: IMDS v1/v2, GCP/Azure metadata, /proc environ scraping for cloud credential theft
domain: cybersecurity
subdomain: credential-theft
tags: [cloud, imds, aws, gcp, azure, credential-theft, container]
version: '1.0'
nist_csf: [PR.AA-05]
mitre_attack: [T1552.005]
---

## When to use

After gaining a foothold on any cloud-hosted target (AWS EC2, GCP Compute,
Azure VM, or a container in any cloud). The loot phase automatically probes
IMDS endpoints and /proc/*/environ.

## What to look for

- **AWS IMDSv1**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  — returns role names + temporary access keys. No auth needed on unpatched hosts.
- **AWS IMDSv2**: requires a PUT token first. The loot module fetches the token
  then uses it for subsequent requests.
- **GCP**: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
  — needs `Metadata-Flavor: Google` header.
- **Azure**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  — needs `Metadata: true` header.
- **/proc/*/environ**: env-injected creds (AWS_ACCESS_KEY_ID, GOOGLE_APPLICATION_CREDENTIALS)
  that never touch a credentials file. Requires root.
- **Docker socket**: `/var/run/docker.sock` — gives root on the host via
  container escape. See the `container-detection-and-escape` skill.

## Why this matters

Cloud creds from IMDS are temporary but valid for 6+ hours. An attacker with
IMDS creds can access S3 buckets, Lambda functions, and other AWS resources
the role has permissions for — often far beyond the single host.