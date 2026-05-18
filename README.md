# Active Directory Auto-Defender

A simple script written in PowerShell, created as part of learning task automation and incident response in a SOC environment (Blue Team / SOAR).

## What does this script do?

The script actively searches Windows Server security logs (Event Viewer) for failed logon attempts (Event ID `4625`). It extracts the IP addresses of potential attackers and, if the predefined threshold of failed attempts is exceeded, it automatically creates an inbound rule in the Windows Defender Firewall to block malicious network traffic originating from Brute Force or Password Spraying attacks.

## How to run it?

1. Open PowerShell as Administrator on the Windows Server (Domain Controller).
2. Optional – ensure that the system execution policy allows running scripts: `Set-ExecutionPolicy RemoteSigned`
3. Run the script: `.\AutoBlock-BruteForce.ps1`
