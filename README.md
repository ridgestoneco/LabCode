eBPF Legacy App Monitoring Lab
A minimal eBPF probe for monitoring legacy application behavior at the kernel level. Built as a learning exercise and companion to a LinkedIn post.
Two files, ~160 lines:
An eBPF C probe that hooks `execve` to catch unexpected process spawns
A Python loader that formats detections as structured JSON and ships to syslog
Tested on Rocky Linux 9. The detection targets T1059, specifically processes like `python`, `curl`, or `perl` spawning shells when they shouldn't.
What this is
A lab. Not production tooling. The point was to see if you could get real-time kernel-level visibility into a legacy app without modifying it. You can.
What it taught me
The eBPF verifier will reject programs it can't prove are safe, even if the logic is correct. String parsing belongs in userspace, not the kernel probe.
Related
LinkedIn writeup with screenshots and context: [link]
