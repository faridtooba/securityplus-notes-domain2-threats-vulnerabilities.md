# securityplus-notes-domain2-threats-vulnerabilities.md

# Domain 2.1 – Threat Actors

### Types of Threat Actors
- **Script Kiddies:** Low skill, use pre-made tools (Nmap, LOIC, Metasploit)
- **Hacktivists:** Politically/socially motivated attackers
- **Organized Crime:** Financially motivated, often behind phishing and ransomware
- **Nation-State / APTs:** Highly skilled, government-backed, focus on espionage
- **Insiders:** Employees, contractors, or vendors with privileged access
- **Competitors:** Espionage for business advantage

### Threat Actor Attributes
- **Sophistication:** Basic → advanced
- **Resources:** Low → unlimited
- **Motivation:** Financial, political, personal, competitive
- **Intent:** Theft, disruption, espionage, sabotage

**SOC Relevance:**
- Helps classify alerts and incidents
- Script kiddies: brute force and scanning attempts
- Organized crime: ransomware, phishing
- Nation-state/APT: long-term persistence, stealthy exfiltration
- Insiders: misuse of privileges, unauthorized access

 Domain 2.2 – Common Threat Vectors

### Definition
A threat vector is the method or path attackers use to gain unauthorized access to a system, network, or data.

### Common Threat Vectors
- **Direct Access:** Physical entry, stolen devices, malicious USB
- **Wireless:** Weak Wi-Fi encryption, rogue APs, evil twin attacks
- **Email:** Phishing, spear phishing, malicious attachments/links
- **Supply Chain:** Vendor compromise, malicious updates (e.g., SolarWinds)
- **Social Media:** Fake accounts, malicious links, social engineering
- **Removable Media:** USB drives, portable disks with malware
- **Cloud:** Misconfigured services, compromised credentials, insecure APIs

**SOC Relevance:**
- Email vectors → phishing alerts in SIEM
- Wireless vectors → IDS alerts for rogue APs
- Supply chain → patch management + vendor monitoring
- Cloud vectors → monitoring IAM logs and API calls

# Domain 2.2 – Phishing

### Definition
Phishing is a social engineering attack where attackers trick users into revealing sensitive information or installing malware.

### Types of Phishing
- **Email Phishing:** Mass campaigns with malicious links or attachments
- **Spear Phishing:** Targeted phishing aimed at specific individuals
- **Whaling:** Spear phishing directed at executives (CEO/CFO)
- **Vishing:** Voice phishing over phone calls
- **Smishing:** SMS/text-based phishing
- **Clone Phishing:** Copy of legitimate email with altered malicious links

### Common Indicators
- Suspicious or spoofed sender address
- Urgent or fear-based language
- Mismatched or hidden URLs
- Unexpected attachments

**SOC Relevance:**
- Analysts investigate phishing alerts in SIEM (blocked emails, DNS lookups to phishing domains)
- Email gateways and DNS sinkholes are critical for detection
- Incident response workflows often start with user-reported phishing

- # Domain 2.2 – Impersonation

### Definition
Impersonation is a social engineering technique where an attacker pretends to be a trusted individual (employee, manager, vendor, or IT staff) to gain access or information.

### Examples
- **Business Email Compromise (BEC):** CEO/CFO impersonation to request wire transfers
- **Help Desk Impersonation:** Fake IT staff requesting password resets
- **Vendor Impersonation:** Fake invoices or bank account change requests
- **Physical Impersonation:** Attacker posing as repair staff or delivery driver

### Techniques
- Authority exploitation (“I’m your manager, approve this now”)
- Urgency (“This must be done immediately”)
- Familiarity with internal terminology or names
- Spoofed phone numbers or email domains

**SOC Relevance:**
- Analysts monitor for spoofed sender domains and abnormal financial transactions
- BEC and impersonation often appear in phishing-related alerts
- Quick escalation is critical since attackers often target executives and finance

# Domain 2.2 – Watering Hole Attacks

### Definition
A watering hole attack compromises a website that a specific group of users visits frequently, using it to deliver malware or steal credentials.

### Process
1. Attacker researches target organization
2. Identifies websites employees visit regularly
3. Compromises those websites (malicious code, redirects, fake forms)
4. Target employees visit site and are infected or tricked

### Example
- Government employees targeted via industry conference website
- Visitors unknowingly downloaded malware

**SOC Relevance:**
- Analysts monitor proxy, DNS, and web logs for unusual domains
- Endpoint security may detect drive-by downloads linked to watering holes
- Threat intel feeds can identify known compromised sites
- Correlation of multiple user infections from same domain is a key detection method

# Domain 2.2 – Other Social Engineering Attacks

### Techniques
- **Pretexting:** Creating a fake scenario to gain trust (e.g., posing as HR or IT)
- **Tailgating / Piggybacking:** Gaining physical access by following an authorized person
- **Eliciting Information:** Extracting data through casual conversation
- **Shoulder Surfing:** Observing sensitive info being entered
- **Dumpster Diving:** Searching trash for confidential documents or devices
- **Hoaxes:** Spreading false alerts or fake news to cause disruption or downloads
- **Quid Pro Quo:** Offering benefits (tech help, gifts) for sensitive information

**SOC Relevance:**
- Badge access logs and cameras help detect tailgating
- Fake alerts (hoaxes) often generate help-desk or SOC tickets
- Analysts document and escalate social-engineering incidents
- Supports user-awareness training and threat reporting processes

# Domain 2.3 – Race Conditions

### Definition
A race condition occurs when multiple processes or threads access a shared resource simultaneously, and the program’s outcome depends on the timing of those events.

### Example (TOCTOU)
- A program checks if a file is safe.
- Attacker replaces the file after the check but before the program uses it.
- Result: attacker’s malicious file runs with elevated privileges.

### Impacts
- Privilege escalation
- Data corruption or inconsistent state
- Denial of Service (crash)

**SOC Relevance:**
- Indicators include rapid file or registry changes from multiple processes.
- EDR/SIEM alerts may show unexpected privilege escalation or modified binaries.
- Analysts correlate timestamps to detect potential TOCTOU exploitation.

# Domain 2.3 – Malicious Updates

### Definition
A malicious update is a legitimate software update modified or replaced to include malicious code. Attackers compromise vendor systems or distribution channels to spread the malware.

### Process
1. Compromise vendor build or update server.
2. Inject malicious code into the update package.
3. Distribute the “trusted” update to users.
4. Victim installs update, executing malicious payload with elevated privileges.

### Real-World Examples
- SolarWinds Orion (2020)
- CCleaner (2017)
- NotPetya (2017)

### Impacts
- Remote code execution
- Supply-chain compromise
- Large-scale data breaches

**SOC Relevance:**
- Monitor EDR/SIEM for new processes, outbound traffic, or registry changes after updates.
- Verify update hashes and digital signatures.
- Use threat intelligence to identify compromised vendor channels.
- Correlate identical post-update anomalies across multiple endpoints.

# Domain 2.3 – Operating System Vulnerabilities

### Definition
Operating system vulnerabilities are weaknesses in OS design, configuration, or code that attackers exploit for unauthorized access or privilege escalation.

### Common Vulnerabilities
- **Privilege Escalation:** Kernel or permission flaws
- **Unpatched Systems:** Missing security updates (known CVEs)
- **Default Credentials:** Factory passwords left unchanged
- **Misconfigurations:** Open ports, weak file or share permissions
- **DLL/Library Hijacking:** Malicious DLLs replacing legitimate ones
- **Driver/Kernel Exploits:** Vulnerable device drivers
- **Insecure Services:** Outdated or unencrypted protocols (Telnet, FTP)

### Impacts
- Privilege escalation
- Malware persistence
- Data theft or service disruption

**SOC Relevance:**
- Monitor EDR/SIEM for privilege-escalation or kernel-level alerts
- Track patch compliance and vulnerability-scan reports
- Detect configuration drift (new ports, disabled defenses)
- Correlate anomalies to identify successful exploitation

# Domain 2.3 – Hardware Vulnerabilities

### Definition
Hardware vulnerabilities are weaknesses in the physical or firmware components of computing devices that attackers can exploit for unauthorized access, data theft, or persistence.

### Common Types
- **Firmware Vulnerabilities:** BIOS/UEFI tampering or outdated firmware
- **CPU Side-Channel Attacks:** Spectre, Meltdown, Foreshadow
- **Supply-Chain Tampering:** Compromised chips or firmware during manufacturing
- **Peripheral/DMA Attacks:** Malicious USBs, PCIe/Thunderbolt access
- **Hardware Backdoors:** Hidden maintenance/debug features
- **Driver/Embedded Code Flaws:** Outdated or signed-but-vulnerable drivers

### Impacts
- Data exfiltration from protected memory
- Persistent access beyond OS control
- Privilege escalation via kernel or firmware flaws
- Large-scale supply-chain compromise

**SOC Relevance:**
- Monitor firmware version changes and BIOS integrity checks
- Watch for DMA, driver exploitation, or kernel-level privilege escalation
- Ensure firmware and microcode patches are tracked and applied
- Escalate cases of persistence surviving re-imaging (possible firmware rootkits)

# Virtualization Vulnerabilities (Security+ SY0-701 — 2.3)

## Summary
Virtualization vulnerabilities are weaknesses in hypervisors, VM images, containers, or management planes that allow attackers to escape isolation, move laterally, or persist across VMs.

## Common Issues
- Hypervisor misconfiguration or unpatched hypervisor CVEs
- VM escape vulnerabilities
- Insecure VM images containing secrets or vulnerable packages
- Excessive privileges for management/service accounts
- Improper snapshot/image handling
- Poor network segmentation in virtual networks
- Insecure container images or orchestration configs

## SOC Relevance / Detection
- Alerts for mass VM creation or snapshot creation (CloudTrail/vSphere logs)
- Unexpected east-west traffic between VMs
- API/service account abuse for creating/modifying instances
- Signs of persistence surviving re-imaging (possible firmware/hypervisor level)

## Defensive Lab Ideas
- Inventory and harden VM images and templates
- Demonstrate secret proliferation from insecure images (lab-only)
- Simulate lateral traffic and build SIEM rules to detect unexpected VM-to-VM flows
- Sandbox cloud account: monitor API calls and detect privileged key abuse

## Mitigations
- Enforce RBAC, least privilege for management accounts
- Patch hosts, hypervisors, and container runtimes
- Use minimal, scanned VM/container images without secrets
- Isolate management plane and use network segmentation/microsegmentation
- Monitor management API logs and snapshot/image activity

# Cloud-Specific Vulnerabilities (Security+ SY0-701 — 2.3)

## Summary
Cloud-specific vulnerabilities stem from shared infrastructure, misconfigurations, insecure APIs, and weak identity or access controls. Exploiting them can lead to data exposure, privilege escalation, or service compromise.

## Common Vulnerabilities
- Misconfigured storage (public S3/Blob buckets)
- Insecure or unauthenticated APIs
- Over-privileged IAM roles / shared credentials
- Data isolation failures and weak encryption
- Shadow IT cloud usage
- Poor key management and unrotated credentials
- Insecure third-party integrations
- Disabled or incomplete audit logging

## SOC Relevance
- Detect abnormal API activity and IAM privilege changes.
- Correlate cloud audit logs with network telemetry for data exfiltration detection.
- Identify newly public resources or modified ACLs.
- Monitor for API abuse and key misuse.

## Defensive Lab Ideas
- AWS S3 exposure and remediation demo.
- API abuse simulation with SIEM correlation.
- IAM key rotation detection.
- Cloud logging verification (CloudTrail / Azure Activity Log).

## Mitigations
- Apply least privilege and MFA for IAM.
- Enable and review audit logging.
- Regularly scan cloud configs with CSPM tools.
- Encrypt data in transit and at rest.
- Rotate keys and disable unused credentials.
- Monitor for public exposure and privilege escalation.

# Supply Chain Vulnerabilities (Security+ SY0-701 — 2.3)

### Summary
Supply-chain vulnerabilities occur when attackers compromise third-party vendors, software updates, or hardware components to infiltrate downstream customers. They exploit trusted relationships to bypass direct defenses.

### Examples
- Trojanized software updates (SolarWinds)
- Exploitable dependencies (Log4j)
- Compromised open-source libraries
- Tampered hardware or firmware
- Unvetted third-party integrations
- Compromised CI/CD pipelines

### Impacts
- Widespread compromise across customers
- Data breaches and backdoor installation
- Loss of vendor trust and operational downtime

### SOC Relevance
- Monitor vendor breach advisories and threat-intel feeds.
- Correlate unusual network activity after updates.
- Detect untrusted code-signing certificates.
- Identify processes/services installed after vendor updates.

### Defensive Lab Ideas
- Verify file hashes and digital signatures of updates.
- Run dependency vulnerability scans (npm audit / pip-audit).
- Simulate IOC hunt for known supply-chain breaches.

### Mitigations
- Maintain a software bill of materials (SBOM).
- Validate signatures/hashes of all software updates.
- Limit vendor network access.
- Perform vendor risk assessments.
- Use continuous vulnerability scanning and CSPM tools.

# Misconfiguration Vulnerabilities (Security+ SY0-701 — 2.3)

## Summary
Misconfiguration vulnerabilities occur when systems are improperly set up, leaving insecure defaults, open ports, or unnecessary privileges that attackers can exploit.

## Common Examples
- Default or weak credentials
- Unrestricted file or bucket permissions
- Open or unused network ports
- Disabled logging or AV
- Firewall rules open to all (0.0.0.0/0)
- Outdated or default application settings

## SOC Relevance
- Detect configuration drift or open ports
- Monitor for disabled security services
- Identify new public cloud resources
- Report misconfiguration findings from scans

## Defensive Lab Ideas
- Harden a local web server and rescan
- Detect cloud misconfigurations (Prowler / ScoutSuite)
- SIEM rule: alert on Defender disabled or ports added
- Password audit for weak credentials

## Mitigations
- Enforce secure configuration baselines
- Apply least privilege
- Use IaC with validation
- Remove unused services and ports
- Enable logging and continuous scanning

 Mobile Device Vulnerabilities (Security+ SY0-701 — 2.3)

## Summary
Mobile vulnerabilities involve weaknesses in device OS, apps, configurations, and networks that attackers exploit to steal data or gain unauthorized access.

## Common Examples
- Outdated OS or apps
- Malicious or side-loaded applications
- Jailbroken/rooted devices
- Weak device configurations
- Unsecured Wi-Fi or Bluetooth connections
- Excessive app permissions / data leakage
- MDM misconfigurations
- Lost or stolen devices

## SOC Relevance
- Monitor MDM/EDR telemetry for rooted devices and outdated OS versions.
- Correlate network logs for suspicious mobile IPs or Wi-Fi.
- Respond to alerts of lost/stolen devices and enforce remote wipe.
- Track mobile malware and phishing campaigns through threat intel.

## Defensive Lab Ideas
- Simulate MDM enrollment and policy violations.
- Capture app permissions and network activity in a test lab.
- Test Wi-Fi interception scenarios safely to demonstrate encryption needs.

## Mitigations
- Enforce MDM policies (PIN, encryption, remote-wipe).
- Keep devices updated and patched.
- Restrict app sources and permissions.
- Block rooted/jailbroken devices.
- Use VPN and HTTPS on public networks.
- Provide user training on mobile phishing and QR code threats.

# Zero-Day Vulnerabilities (Security+ SY0-701 — 2.3)

## Summary
A zero-day vulnerability is a previously unknown flaw with no available patch, often exploited before the vendor or defenders are aware. Detection relies on anomaly-based monitoring and threat intelligence rather than signatures.

## Key Concepts
- Zero-day vulnerability: unknown flaw not yet patched
- Zero-day exploit: code exploiting that flaw
- Zero-day attack: real-world use of such an exploit
- N-day vulnerability: known, patch available, but still dangerous

## SOC Relevance
- Monitor behavioral anomalies and unusual outbound traffic
- Use threat intel feeds to track emerging zero-days
- Rapid patching once fixes are released
- Hunt for post-compromise indicators (new processes, persistence)
- Correlate logs from EDR, firewall, and threat feeds

## Defensive Lab Ideas
- Behavioral detection with EDR/SIEM for unexpected process activity
- Feed-based alerting for new zero-days (CISA KEV, Exploit-DB)
- Patch lifecycle documentation exercise for major vulnerabilities

## Mitigations
- Defense in depth and least privilege
- Behavioral and heuristic EDR detection
- Centralized threat intelligence integration
- Frequent patching and secure baselines
- Application whitelisting and segmentation
- Incident response plan for rapid isolation

# An Overview of Malware — Security+ SY0-701 (2.4)

### Definition
Malware is malicious software designed to damage systems, steal information, or provide unauthorized access.

### Major Types
- Virus – file infection and replication
- Worm – self-spreading without user interaction
- Trojan – appears legitimate but includes malicious code
- Ransomware – encrypts data and demands payment
- Spyware – monitors and steals information
- Adware – unwanted advertising behavior
- Rootkit – hides processes, files, and activity
- Logic Bomb – delayed or triggered malicious action
- Botnet Agent – enables remote C2 control

### SOC Relevance
- Analyze EDR/AV alerts, DNS logs, network traffic, and process anomalies
- Extract IOCs (hashes, filenames, domains, C2 IPs)
- Contain, eradicate, recover, and document incidents

### Indicators of Malware
- Unexpected processes or network connections
- File encryption or mass renaming
- Browser hijacking or unsolicited ads
- Disabled security tools
- Outbound traffic to suspicious domains

# Viruses and Worms — Security+ SY0-701 (2.4)

## Viruses
A virus is malware that attaches to a host file and requires user action to spread. It replicates by infecting files or applications.

### Characteristics
- Needs user interaction
- Needs a host file/program
- Spreads through attachments, downloads, USB devices
- Often corrupts or modifies files

## Worms
A worm is self-replicating malware that spreads automatically across networks using vulnerabilities or weak credentials.

### Characteristics
- No user interaction required
- Does not need a host file
- Scans network and spreads on its own
- Causes traffic spikes and rapid infection

## Differences (Virus vs Worm)
- Virus = manual spread, needs host  
- Worm = automatic spread, network-based  

## SOC Relevance
- Detect file changes (virus)
- Detect scanning and lateral movement (worm)
- Identify patient zero and isolate quickly
- Review AV/EDR detections and network logs

## Mitigation
- Patch systems and services (SMB/RDP vulnerabilities)
- Use EDR and antivirus
- Disable autorun and unnecessary services
- Segment networks to limit worm spread
- Educate users not to open suspicious attachments
### Mitigation
- Behavioral EDR and AV tools
- Email and web filtering
- Network segmentation
- Backups and ransomware readiness
- Patching and hardening

# Spyware & Bloatware — Security+ SY0-701 (2.4)

## Spyware
Spyware is malicious software that secretly collects user information (keystrokes, passwords, screenshots, browser data) without permission.

### Types
- Keyloggers
- Credential stealers
- Screen capture spyware
- Monitoring/stalkerware

### SOC Relevance
- Detect unknown processes or extensions
- Identify abnormal outbound connections
- Investigate credential-stealing behavior
- Review EDR alerts for keylogging/screenshot activity

## Bloatware
Bloatware refers to pre-installed or unwanted software that slows devices, uses resources, or displays ads. Not always malicious, but it increases the attack surface.

### SOC Relevance
- Monitor CPU/memory usage spikes
- Review user reports of slow devices
- Flag adware-related activity
- Recommend device hardening and removal

## Mitigations
- Use EDR and AV tools
- Remove bloatware via standard images
- Patch OS and apps
- Limit admin rights
- Monitor outbound network traffic

# Other Malware Types — Security+ SY0-701 (2.4)

## Fileless Malware
- Runs in memory using built-in tools (PowerShell, WMI).
- Hard to detect because no file is written to disk.
- SOC: monitor ScriptBlock logs, abnormal PowerShell usage, parent-child process chains.

## Rootkits
- Hide malware by modifying the OS or kernel.
- Can hide processes, files, or registry keys.
- SOC: look for hidden processes, mismatched system file hashes, disabled security controls.

## Bootkits
- Rootkits that infect the bootloader.
- Load before the OS and gain full control early.
- SOC: monitor bootloader integrity, secure boot logs.

## Logic Bombs
- Malicious code triggered by a date/event.
- Often insider-planted.
- SOC: watch for unusual scheduled tasks, timed anomalies.

## Polymorphic Malware
- Changes its code to evade detection.
- Uses encryption or mutation engines.
- SOC: rely on behavioral detection and EDR.

## Armored Malware
- Designed to prevent analysis (anti-debug, anti-VM).
- SOC: use sandboxing and behavioral analysis.

## Mitigations
- EDR with memory scanning
- Disable unused scripting engines
- Patching and hardening
- Application whitelisting
- Strong monitoring and baselines

# Denial of Service (DoS / DDoS) — Security+ SY0-701 (2.4)

## Definition
A Denial of Service (DoS) attack attempts to make a system or service unavailable by overwhelming it with traffic or forcing it to crash.  
A Distributed DoS (DDoS) attack uses many devices (often a botnet) to amplify the attack.

## Types of DoS/DDoS
- DoS (single source)
- DDoS (botnets, massive traffic)
- Application-level attacks (Slowloris, API floods)
- Protocol attacks (SYN flood, UDP flood, Smurf)
- Resource exhaustion (CPU, RAM, disk)

## SOC Relevance
- Detect traffic spikes and large numbers of requests
- Watch for SYN flood patterns
- Identify botnet traffic behavior
- Use ISP or cloud DDoS protection
- Check for intrusion attempts hidden behind the noise

## Indicators
- Slow or unreachable services
- High CPU / network usage
- Many requests from same IP or many IPs
- Half-open TCP connections

# DNS Attacks — Security+ SY0-701 (2.4)

## Overview
DNS (Domain Name System) can be attacked to redirect traffic, steal data, hide C2 channels, or perform DDoS attacks.

## Common DNS Attacks
- **DNS Poisoning / Cache Poisoning:** fake DNS records return malicious IPs.
- **DNS Spoofing:** attacker impersonates DNS server.
- **DNS Hijacking:** DNS settings changed on routers, devices, or domain accounts.
- **DNS Tunneling:** attackers hide data/C2 traffic inside DNS queries.
- **DNS Amplification:** uses open resolvers to amplify DDoS attacks.
- **Typosquatting:** fake domain names look similar to real ones.

## SOC Indicators
- Long or random DNS queries (tunneling)
- DNS answers from unexpected servers
- Traffic spikes to/from DNS port 53
- Many different DNS answers for same domain
- Requests to suspicious or lookalike domains

## Mitigation
- DNSSEC
- Block unauthorized DNS servers
- Monitor DNS logs for anomalies
- Response rate limiting
- Secure DNS resolvers
- Patch DNS infrastructure
- Use MFA for domain registrar accounts
## Mitigations
- Rate limiting and WAF
- Firewall filtering and geo-blocking
- Load balancing and autoscaling
- DDoS scrubbing via cloud providers
- System patching and hardening

# Wireless Attacks — Security+ SY0-701 (2.4) — Professor Messer Summary

## Rogue Access Point
Unauthorized access point placed on the network; used for MITM and traffic interception.

## Evil Twin
Fake AP with identical SSID to trick users into connecting. Captures credentials and sessions.

## Wireless Jamming
Flooding radio frequencies to disrupt connectivity. Includes constant, intermittent, and reactive jamming.

## Deauthentication Attacks
Spoofed deauth frames disconnect clients to force reconnection. Used to capture WPA2 handshakes.

## WPS Attacks
WPS PIN is vulnerable to brute force → attacker gains Wi-Fi password. Should be disabled.

## Bluetooth Attacks
- **Bluejacking:** unsolicited messages.
- **Bluesnarfing:** data theft.
- **Bluebugging:** full device control.

## RFID/NFC Attacks
Cloning, replay attacks, relay attacks, unauthorized reading of badges or NFC payments.

## SOC Relevance
- Watch for rogue APs, evil twins, and unknown SSIDs.
- Monitor for DHCP leases from unauthorized devices.
- Detect repeated deauth events.
- Investigate abnormal wireless connections or MAC addresses.
- Ensure WPS is disabled and Wi-Fi uses WPA3.
