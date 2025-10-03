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

