# Release Sentinel public challenge — safe harbor and scope

This repository invites good-faith security research against **Release
Sentinel's challenge fixtures and trust model**, not against unrelated systems.

## In scope

- local copies / forks of this repository;
- the published challenge container and fixtures;
- adversarial advisory output, prompt injection, memory poisoning, malformed
  structured output, replay attempts, concurrency attempts, serialization edge
  cases, remediation-boundary tests, and novel techniques that test a stated
  Release Sentinel invariant;
- responsible disclosure of a reproducible authority break.

## Out of scope

- attacking Google, GitHub, package registries, CI providers, maintainers, judges,
  other researchers, or third parties;
- credential theft, phishing, social engineering, DDoS / resource exhaustion,
  malware deployment, persistence outside a disposable test environment, or
  accessing data you do not own;
- using real customer data or production credentials;
- exploiting the host/container runtime itself as a substitute for breaking the
  Release Sentinel trust model.

## Safety rule

Public attack code must run only in disposable, secret-free infrastructure. The
provided Docker profile is for local defense-in-depth; internet-facing arbitrary
code execution should add a VM/microVM-grade isolation boundary and strict
resource quotas.

Good-faith reports that stay inside this scope are welcomed. This document is a
project policy, not a promise that overrides applicable law or a third party's
terms of service.
