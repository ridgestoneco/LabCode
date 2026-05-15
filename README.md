# eBPF Legacy App Monitoring Lab

A minimal eBPF probe for monitoring legacy application behavior at the kernel level.

Built as a learning exercise and companion to a LinkedIn writeup exploring lightweight runtime visibility for legacy applications without modifying the application itself.

## Overview

This project contains two small components:

- An eBPF C probe that hooks `execve` to monitor unexpected process execution
- A Python loader that formats detections as structured JSON and forwards them to syslog

Total size: approximately 160 lines of code.

Tested on Rocky Linux 9.

## Detection Focus

The lab focuses on ATT&CK technique:

- T1059 – Command and Scripting Interpreter

Example behaviors monitored:

- `python` spawning shells unexpectedly
- `curl` executing shell commands
- `perl` launching child interpreters
- Legacy applications spawning interactive shells

The goal is not signature detection. The goal is visibility into unusual process execution paths at the kernel boundary.

## What This Is

This is a lab and learning exercise.

It is not production tooling.

The purpose of the project was to answer a simple question:

> Can you get meaningful, real-time kernel-level visibility into a legacy application without modifying the application itself?

The answer is yes.

## What It Taught Me

A few practical lessons became obvious very quickly:

- The eBPF verifier rejects programs it cannot mathematically prove are safe, even when the logic itself is valid
- Keeping kernel probes minimal dramatically improves stability and portability
- String parsing and enrichment belong in userspace, not inside the kernel probe
- Structured telemetry is far easier to work with once emitted as JSON outside the probe itself

## Example Workflow

1. Legacy application launches a child process
2. eBPF probe hooks the `execve` syscall
3. Event metadata is passed to userspace
4. Python loader formats the event as JSON
5. Detection is forwarded to syslog or SIEM tooling

## Environment

Validated on:

- Rocky Linux 9
- Modern Linux kernel with eBPF support enabled

## Related Writeup

LinkedIn writeup with screenshots, implementation notes, and additional context:

[Add LinkedIn link here]

## License

MIT
