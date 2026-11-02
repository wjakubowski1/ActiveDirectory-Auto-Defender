## Active Directory Auto-Defender

A simple script written in PowerShell, created as part of learning task automation and incident response in a SOC environment.

### Current Features

The script actively searches Windows Server security logs (Event Viewer) for failed logon attempts (Event ID `4625`). It extracts the IP addresses of potential attackers and, if the predefined threshold of failed attempts is exceeded, it automatically creates an inbound rule in the Windows Defender Firewall to block malicious network traffic originating from Brute Force or Password Spraying attacks.

### How to run

- Open PowerShell as Administrator on the Windows Server (Domain Controller).
- (Optional) Ensure that the system execution policy allows running scripts: `Set-ExecutionPolicy RemoteSigned`
- Run the script: `.\AutoBlock-BruteForce.ps1`
