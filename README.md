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
