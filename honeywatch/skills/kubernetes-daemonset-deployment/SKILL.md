---
name: kubernetes-daemonset-deployment
description: Deploy the miner as a Kubernetes DaemonSet for cluster-wide persistence using recovered service account tokens
domain: cybersecurity
subdomain: persistence
tags: [persistence, k8s, daemonset, cluster, lateral, T1078.004]
version: '1.0'
nist_csf: [PR.DS-01]
mitre_attack: [T1078.004]
---

## When to use

When the loot phase recovers a Kubernetes service account token
(`/var/run/secrets/kubernetes.io/serviceaccount/token`) or kubeconfig from a
compromised container. A single k8s cluster with 100 nodes = 100 miners from
one compromise.

## What it does

The `k8s_daemonset` payload:
- Authenticates to the Kubernetes API server using the recovered token
- Creates a DaemonSet that schedules the miner pod on every node
- The pod runs with `hostPID` and `hostNetwork` for full node access
- Uses `kubectl` if available, falls back to `curl` for direct API calls
- The DaemonSet spec uses `_esc_sed()` for safe sed replacement in templates

## OPSEC notes

- kubectl and curl API calls are logged by Kubernetes audit logging
- DaemonSets are visible via `kubectl get daemonsets`
- The pod spec uses a system-like name (`system-node-config`) for blending
- If the service account token is rotated, the DaemonSet will stop receiving updates
- Pair with `firewall_disable` to ensure the miner can reach the pool from all nodes