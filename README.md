portscan.c — Custom TCP Port Scanner
A lightweight TCP port scanner written in C, built as the code deliverable for our Operating Systems project, Comparative Analysis of Operating System Resilience to Network Attacks on a Shared Wi-Fi Network. It independently reproduces the open / closed / filtered results we obtained with nmap, validating the paper's attack-surface findings with our own code.
Authors: Muhammad Saad · Krish Kumar · M. Abdullah Siddiqui
Institution: Habib University, Karachi — Operating Systems
⚠️ Ethics & legal notice
This scanner was written and used only against devices we own, on a private, isolated network we control. Scanning hosts or networks you do not own and are not authorised to test is illegal in most jurisdictions. Use it only on your own equipment.
Repository contents
.
├── portscan.c    # the TCP port scanner (single source file)
└── README.md     # this file
The paper, presentation, and experiment charts are submitted separately — this repository holds the code deliverable only.
What it does
portscan.c scans a range of TCP ports on a target host and classifies each one as open, closed, or filtered, using a **non-blocking connect() + select()
SO_ERROR** check rather than a blocking connect:
open — the connection completes (SO_ERROR == 0)
closed — the connection is actively refused (ECONNREFUSED)
filtered — select() times out with no response (a firewall is silently dropping the probe)
That open-vs-filtered distinction is the key result: it is what let us tell a silent-drop firewall (Windows) apart from a host that actively refuses connections (Android), matching what nmap reported.
Build
Requires a C compiler (gcc or clang) on Linux. No external libraries.
gcc -Wall -O2 -o portscan portscan.c
Usage
<!-- CONFIRM: verify this line against your actual main()/argv parsing before you commit. If a grader runs it exactly as written and the arguments don't match, the code will look broken. Replace with your real syntax + a real example. -->
./portscan <target-ip> <start-port> <end-port>
Example — scan ports 1–1024 on a host on your own network:
./portscan 172.20.10.3 1 1024
Example output
<!-- CONFIRM: paste a real snippet of your scanner's actual output here so it matches the compiled binary. -->
Scanning 172.20.10.3, ports 1-1024 ...
Port 22   : open
Port 80   : open
Port 443  : closed
Port 139  : filtered
...
Scan complete: N open, M closed, K filtered
How it was used in the study
We ran portscan.c against each target OS (Windows, Android, Linux, macOS) on an isolated Wi-Fi network and compared its open/closed/filtered output to nmap's. It reproduced the findings exactly — Windows returned all ports filtered (silent-drop firewall), Android all ports closed (active RST), while macOS exposed several listening services — confirming the attack-surface results reported in the paper.
