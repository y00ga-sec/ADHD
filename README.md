# Active Directory Honeypot Deployment Toolkit
This PowerShell script is designed to help Blue Teams and security researchers deploy a variety of Active Directory honeypots to detect unauthorized access, reconnaissance, or credential harvesting attempts in enterprise environments. I also wrote a [blogpost](https://blog.y00ga.lol/PERSO/CYBER/PUBLISH/Article+perso/Hardening+by+Deception+-+Deploying+Active+Directory+Honeypots) about it if you want to know more about those honeypot objects 

### Features
The script supports deploying and monitoring several types of deceptive objects within an Active Directory (AD) domain, including:

- AS-REP Roasting Honeypot Accounts
- Kerberoastable Service Accounts
- Generic Honeypot User Accounts
- Pre-Windows 2000 Style Machine Accounts
- GPO Autologon Credential Traps
- Fake High-Value GPO Traps
- GPO Access Monitoring (SACL Auditing)

These honeypots are intentionally misconfigured or made to appear vulnerable, providing early detection for common attack techniques like:

- AS-REP Roasting
- Kerberoasting
- GPO password scraping
- Unauthorized read/write access
- Reconnaissance targeting GPOs or accounts

### Prerequisites

- PowerShell 5.1+
- ActiveDirectory and GroupPolicy modules (install via RSAT)
- Domain Admin or equivalent privileges
- Logging enabled (Security log auditing for event IDs 4624, 4625, 4662, 4768, 4769)

### Functions Overview

| Function                             | Description                                                                                                                 |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `New-ASRepRoastableHoneypotAccount`  | Creates a user without Kerberos pre-authentication. Triggers on Event ID 4768 with failure code 0x18 or 0x19.               |
| `New-KerberoastableHoneypotAccount`  | Creates a service account with a Service Principal Name (SPN). Triggers on Event ID 4769.                                   |
| `New-HoneypotUserAccount`            | Deploys a user with no password and domain-level `Deny All` ACLs. Triggers on any login or access attempts.                 |
| `New-PreW2K-HoneypotComputerAccount` | Simulates legacy machine accounts with known password (machine name). Useful against legacy brute-force and scanning tools. |
| `New-HoneyGPOAutologon`              | Creates a GPO with fake plaintext credentials in SYSVOL. Triggers on access attempts or credential use.                     |
| `Enable-AllGpoAuditing`              | Enables SACL auditing on all GPO folders in SYSVOL. Detects unauthorized reads (event 4662).                                |
| \`New-HoneyGpoAccess                 |                                                                                                                             |


### Monitoring Guide
Make sure to configure your SIEM or log monitoring solution to watch for:

| Event ID    | Description                                              |
| ----------- | -------------------------------------------------------- |
| 4624 / 4625 | Successful or failed login attempts to honeypot accounts |
| 4662        | Attempted object property access (read/write)            |
| 4768        | Kerberos TGT request (with or without pre-auth)          |
| 4769        | Kerberos service ticket request for SPNs                 |
| File Access | Read access to SYSVOL files (for GPP/GPO traps)          |


### Usage Examples

````
# Create an AS-REP roasting honeypot
New-ASRepRoastableHoneypotAccount -OU "OU=HoneyUsers,DC=corp,DC=local" -AccountName "svc_roastbait"
````
````
# Create a Kerberoastable honeypot
New-KerberoastableHoneypotAccount -OU "OU=HoneyUsers,DC=corp,DC=local" -AccountName "svc_kerbbait" -ServicePrincipalName "MSSQLSvc/fake-sql.corp.local"
````
````
# Deploy a honeypot user account with auditing and deny ACLs
New-HoneypotUserAccount -OU "OU=HoneyUsers,DC=corp,DC=local" -UserName "fake_admin"
````
````
# Setup a GPP autologon trap with dummy credentials
New-HoneyGPPAutologon -GpoName "GPP-Honey" -HoneyUsername "baituser" -HoneyPassword "P@ssw0rd123!" -LinkTarget "OU=Workstations,DC=corp,DC=local"
````
````
# Create fake GPO trap
New-HoneyGpoAccessTrap -GpoName "Domain Admins - Password Policy"
````
````
# Enable auditing across all GPOs
Enable-AllGpoAuditing
````

***Important*** : Always validate the OU paths and test in a lab before deploying to production.

⚠️ These honeypots are designed to look real and vulnerable, but should not be used in production environments without appropriate controls and monitoring in place. Misuse or incorrect deployment may inadvertently expose false credentials or create confusion.
